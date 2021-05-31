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
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/PinkNoize/tls-observatory/internal/database"
	"github.com/PinkNoize/tls-observatory/internal/util"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v6"
	"github.com/vbauerster/mpb/v6/decor"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// transvalidateCmd represents the transvalidate command
var transvalidateCmd = &cobra.Command{
	Use:   "transvalidate",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := findTransvalidCerts()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(transvalidateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// transvalidateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// transvalidateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func findTransvalidCerts() error {
	db, err := util.PromptDB()
	if err != nil {
		return err
	}
	fmt.Println("Inserting Root CAs...")
	rootCAs, err := getRootCAs(db)
	if err != nil {
		return err
	}

	cur, err := db.GetUntransvalidatedCerts()
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
		t, err := time.Parse(time.RFC3339, doc.Data.TLS.Timestamp)
		if err != nil {
			log.Println(err)
			continue
		}
		err = checkTransValidCertFromIDs(db, rootCAs, name, t, id, siteCert, chain)
		if err != nil {
			log.Println(err)
		}
	}
	bar.SetTotal(0, true)
	p.Wait()

	return nil
}

func checkTransValidCertFromIDs(db *database.Database, rootCAs map[string]*x509.CertPool, name string, t time.Time, id, siteCert primitive.ObjectID, chain []primitive.ObjectID) error {
	// This code is that same as in validate with intermediate cert searching
	siteIsTransValid := false
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

	// Look for candidate intermediate certificates
	strAKID := strings.ToLower(hex.EncodeToString(realSiteCert.AuthorityKeyId))
	var certAKID interface{} = strAKID
	if len(strAKID) == 0 {
		certAKID = nil
	}
	certIssuer := siteCertInfo["parsed"].(bson.M)["issuer_dn"]
	cursor, err := db.AllCerts.Find(context.TODO(),
		bson.M{
			"valid": true,
			"parsed.extensions.basic_constraints.is_ca": true,
			"parsed.subject_dn":                         certIssuer,
			"parsed.extensions.subject_key_id":          certAKID,
		},
		options.Find().SetProjection(bson.M{
			"raw": 1,
			"_id": 1,
		}),
	)
	if err != nil {
		return err
	}

	// Add each potential to the chain
	for cursor.Next(context.TODO()) {
		var immCert struct {
			Raw string             `bson:"raw"`
			id  primitive.ObjectID `bson:"_id"`
		}
		if err = cursor.Decode(&immCert); err != nil {
			return err
		}
		realImmCert, err := parseCertB64(immCert.Raw)
		if err != nil {
			return err
		}
		realChain.AddCert(realImmCert)
		allCertsArray = append(allCertsArray,
			pair{immCert.id,
				realImmCert,
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
			CurrentTime:   t,
		})
		if err != nil {
			log.Println(err)
			continue
		}
		if len(validChains) > 0 {
			siteIsTransValid = true
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
	err = db.SetScanValidation(id, siteIsTransValid, true)
	return err
}
