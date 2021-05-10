/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/PinkNoize/tls-observatory/internal/database"
	"github.com/PinkNoize/tls-observatory/internal/dataset"
	"github.com/PinkNoize/tls-observatory/internal/util"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v6"
	"github.com/vbauerster/mpb/v6/decor"
	ztls "github.com/zmap/zcrypto/tls"
	zx509 "github.com/zmap/zcrypto/x509"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := validateCertChains()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// validateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// validateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func getRootCAs(db *database.Database) (map[string]*x509.CertPool, error) {
	rootCAs := make(map[string]*x509.CertPool)
	err := filepath.Walk(dataset.ROOTCAS_PATH, func(path string, info os.FileInfo, err error) error {
		filename := info.Name()
		if match, _ := filepath.Match("*.pem", filename); match {
			rootName := strings.TrimSuffix(filename, filepath.Ext(filename))
			rawPem, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(rawPem)
			rootCAs[rootName] = pool

			var rootCerts []*zx509.Certificate
			// Read all the pem certs
			for {
				block, rest := pem.Decode(rawPem)
				if block == nil {
					break
				}
				if block.Type == "CERTIFICATE" {
					cert, err := zx509.ParseCertificate(block.Bytes)
					if err != nil {
						log.Println(err)
						rawPem = rest
						continue
					}
					rootCerts = append(rootCerts, cert)
				} else {
					log.Printf("PEM data not a certificate: %v", block.Type)
				}
				rawPem = rest
			}
			for _, cert := range rootCerts {
				formattedCert := ztls.SimpleCertificate{
					Raw:    cert.Raw,
					Parsed: cert,
				}
				jsonFormat, err := json.Marshal(formattedCert)
				if err != nil {
					log.Printf("Failed to marshal json: %v", err)
					continue
				}
				var certInfo bson.M
				err = bson.UnmarshalExtJSON(jsonFormat, true, &certInfo)
				if err != nil {
					log.Printf("Failed to unmarshal bson: %v", err)
					continue
				}
				certInfo["isRootCA"] = true
				certInfo["valid"] = true
				certInfo["validRoots"] = bson.A{rootName}
				id, err := db.InsertCert(certInfo, true)
				if err != nil {
					log.Printf("Failed to insert cert: %v", err)
					continue
				}

				_, err = db.AllCerts.UpdateByID(context.TODO(),
					id,
					bson.M{
						"$set": bson.M{
							"isRootCA": true,
							"valid":    true,
						},
						"$addToSet": bson.M{
							"validRoots": rootName,
						},
					},
				)
				if err != nil {
					log.Println(err)
				}
			}
		}
		return nil
	})
	return rootCAs, err
}

func validateCertChains() error {
	db, err := util.PromptDB()
	if err != nil {
		return err
	}
	fmt.Println("Inserting Root CAs...")
	rootCAs, err := getRootCAs(db)
	if err != nil {
		return err
	}
	cur, err := db.GetUnvalidatedCerts()
	if err != nil {
		return err
	}

	// Setup Ctrl-C handler
	signalChan := make(chan os.Signal, 1)
	stopLooping := make(chan struct{})
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		fmt.Printf("Stopping...\n\n\n")
		stopLooping <- struct{}{}
		signal.Stop(signalChan)
	}()

	// Setup progress bar
	p := mpb.New()
	bar := p.AddBar(0,
		mpb.PrependDecorators(decor.Counters(0, "%v iter [%v]")),
	)

mainLoop:
	for cur.Next(context.TODO()) {
		bar.IncrBy(1)
		// Check if we should stop
		select {
		case <-stopLooping:
			break mainLoop
		default:
		}

		var name string
		var doc database.ZGrabResponse
		err = cur.Decode(&doc)
		if err != nil {
			continue
		}
		if doc.ID == nil {
			log.Printf("Document does not contain an _id: %+v\n", doc)
			continue
		}
		if doc.Domain != nil {
			name = *doc.Domain
		} else if doc.IP != nil {
			name = *doc.IP
		} else {
			log.Printf("Document does not contain \"domain\" or \"ip\": %+v\n", doc)
			continue
		}
		if doc.Data == nil {
			continue
		}
		if doc.Data.TLS == nil {
			continue
		}
		if doc.Data.TLS.Result == nil {
			continue
		}
		if doc.Data.TLS.Result.HandshakeLog == nil {
			continue
		}
		if doc.Data.TLS.Result.HandshakeLog.ServerCertificates == nil {
			continue
		}
		if doc.Data.TLS.Result.HandshakeLog.ServerCertificates.Certificate == nil {
			continue
		}
		cert := *doc.Data.TLS.Result.HandshakeLog.ServerCertificates.Certificate
		siteCert, ok := cert.(primitive.ObjectID)
		if !ok {
			log.Printf("\"Certificate\" not an objectID: %v\n", cert)
			continue
		}
		var chain []primitive.ObjectID
		if doc.Data.TLS.Result.HandshakeLog.ServerCertificates.Chain != nil {
			for _, idTmp := range *doc.Data.TLS.Result.HandshakeLog.ServerCertificates.Chain {
				id, ok := idTmp.(primitive.ObjectID)
				if !ok {
					log.Printf("\"Chain[]\" not an objectID: %v\n", idTmp)
					continue
				}
				chain = append(chain, id)
			}
		}
		id, ok := (*doc.ID).(primitive.ObjectID)
		if !ok {
			log.Printf("_id is not an ObjectID: %T\n", doc.ID)
			continue
		}
		err = validateCertsFromIDs(db, rootCAs, name, id, siteCert, chain)
		if err != nil {
			log.Println(err)
		}
	}
	bar.SetTotal(0, true)
	p.Wait()

	return nil
}

func parseCertB64(b64Cert string) (*x509.Certificate, error) {
	b64decoder := base64.StdEncoding
	rawDERCert, err := b64decoder.DecodeString(b64Cert)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(rawDERCert)
}

func validateCertsFromIDs(db *database.Database, rootCAs map[string]*x509.CertPool, name string, id, siteCert primitive.ObjectID, chain []primitive.ObjectID) error {
	siteIsValid := false
	siteCertInfo, err := db.GetCertByID(siteCert)
	if err != nil {
		return err
	}
	rawSiteCert_i, ok := siteCertInfo["raw"]
	if !ok {
		return fmt.Errorf("document does not contain \"raw\"")
	}
	rawSiteCert, ok := rawSiteCert_i.(string)
	if !ok {
		return fmt.Errorf("\"raw\" not a string: %T", rawSiteCert_i)
	}
	realSiteCert, err := parseCertB64(rawSiteCert)
	if err != nil {
		return err
	}
	realChain := x509.NewCertPool()
	type pair struct {
		id       primitive.ObjectID
		cert     *x509.Certificate
		validCAs map[string]struct{}
		isRootCA bool
	}

	var allCertsArray []pair
	// Add the site cert
	allCertsArray = append(allCertsArray,
		pair{siteCert,
			realSiteCert,
			make(map[string]struct{}),
			false,
		},
	)

	for i := range chain {
		curCertInfo, err := db.GetCertByID(chain[i])
		if err != nil {
			return err
		}
		rawCurCert_i, ok := curCertInfo["raw"]
		if !ok {
			return fmt.Errorf("document does not contain \"raw\"")
		}
		rawCurCert, ok := rawCurCert_i.(string)
		if !ok {
			return fmt.Errorf("\"raw\" not a string: %T", rawCurCert_i)
		}
		realCurCert, err := parseCertB64(rawCurCert)
		if err != nil {
			return err
		}
		realChain.AddCert(realCurCert)
		allCertsArray = append(allCertsArray,
			pair{chain[i],
				realCurCert,
				make(map[string]struct{}),
				false,
			},
		)
	}
	for rootName, root := range rootCAs {
		validChains, err := realSiteCert.Verify(x509.VerifyOptions{
			Roots:         root,
			DNSName:       name,
			Intermediates: realChain,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			log.Println(err)
			continue
		}
		if len(validChains) > 0 {
			siteIsValid = true
		}
		for _, validChain := range validChains {
			for chainIndex, validCert := range validChain {
				// Find the ID for the Cert
				for j := range allCertsArray {
					if validCert.Equal(allCertsArray[j].cert) {
						// Mark Cert as Valid
						allCertsArray[j].validCAs[rootName] = struct{}{}
						if chainIndex+1 == len(validChain) {
							allCertsArray[j].isRootCA = true
						}
						break
					}
				}
			}
		}
	}
	for _, cert := range allCertsArray {
		err = db.SetCertValidation(cert.id, cert.validCAs)
		if err != nil {
			return err
		}
	}
	err = db.SetScanValidation(id, siteIsValid)
	return err
}
