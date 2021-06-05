package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const CREDS_FILE = "output/dbcreds.json"
const CERT_DB = "tls-observatory"
const SCANINFO_COL = "scanInfo"
const ALLCERT_COL = "allCerts"

const BUFFER_SIZE = 650

type Database struct {
	client       *mongo.Client
	certDB       *mongo.Database
	ScanInfo     *mongo.Collection
	AllCerts     *mongo.Collection
	resultBuffer []bson.M
}

type databaseConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hostname string `json:"hostname"`
	Dbname   string `json:"dbname"`
}

type ZGrabResponse struct {
	ID     *interface{} `json:"_id" bson:"_id"`
	Domain *string      `json:"domain" bson:"domain"`
	IP     *string      `json:"ip" bson:"ip"`
	Data   *struct {
		TLS *struct {
			Timestamp string `json:"timestamp" bson:"timestamp"`
			Status    string `json:"status" bson:"status"`
			Error     string `json:"error" bson:"error"`
			Result    *struct {
				HandshakeLog *struct {
					ServerCertificates *struct {
						Certificate *interface{}   `json:"certificate" bson:"certificate"`
						Chain       *[]interface{} `json:"chain" bson:"chain"`
					} `json:"server_certificates" bson:"server_certificates"`
				} `json:"handshake_log" bson:"handshake_log"`
			} `json:"result" bson:"result"`
		} `json:"tls" bson:"tls"`
	} `json:"data" bson:"data"`
}

func CreateDatabase(user, pass, host string) (*Database, error) {
	client, err := mongo.NewClient(options.Client().
		ApplyURI(
			fmt.Sprintf("mongodb://%s",
				host,
			),
		).
		SetAuth(
			options.Credential{
				Username: user,
				Password: pass,
			},
		),
	)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = client.Connect(ctx); err != nil {
		client.Disconnect(ctx)
		return nil, err
	}
	if err = client.Ping(ctx, nil); err != nil {
		client.Disconnect(ctx)
		return nil, err
	}

	cfg := databaseConfig{
		Username: user,
		Password: pass,
		Hostname: host,
	}
	if err = storeDatabaseCfg(&cfg); err != nil {
		client.Disconnect(ctx)
		return nil, err
	}
	self, err := New(client)
	return &self, err
}

func storeDatabaseCfg(cfg *databaseConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(CREDS_FILE, data, 0400)
	return err
}

func getDatabaseCfg() (*databaseConfig, error) {
	data, err := ioutil.ReadFile(CREDS_FILE)
	if err != nil {
		return nil, err
	}
	var cfg databaseConfig
	if err = json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func OpenDatabase() (*Database, error) {
	cfg, err := getDatabaseCfg()
	if err != nil {
		return nil, err
	}
	client, err := mongo.NewClient(options.Client().
		ApplyURI(
			fmt.Sprintf("mongodb://%s",
				cfg.Hostname,
			),
		).
		SetAuth(
			options.Credential{
				Username: cfg.Username,
				Password: cfg.Password,
			},
		),
	)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = client.Connect(ctx); err != nil {
		client.Disconnect(ctx)
		return nil, err
	}
	if err = client.Ping(ctx, nil); err != nil {
		client.Disconnect(ctx)
		return nil, err
	}
	self, err := New(client)
	return &self, err
}

func New(client *mongo.Client) (Database, error) {
	db := client.Database(CERT_DB)
	allCerts := db.Collection(ALLCERT_COL)
	scanInfo := db.Collection(SCANINFO_COL)
	preventDupsCerts := mongo.IndexModel{
		Keys: bson.M{
			"parsed.fingerprint_sha256": 1,
		}, Options: options.Index().SetUnique(true),
	}
	_, err := allCerts.Indexes().CreateOne(context.TODO(), preventDupsCerts)
	if err != nil {
		return Database{}, err
	}
	rootCAIndex := mongo.IndexModel{
		Keys: bson.M{
			"isRootCA": 1,
		},
		Options: options.Index().
			SetPartialFilterExpression(bson.M{
				"isRootCA": true,
			}),
	}
	_, err = allCerts.Indexes().CreateOne(context.TODO(), rootCAIndex)
	if err != nil {
		return Database{}, err
	}
	// Index for speeding up transvalid queries
	immIndex := mongo.IndexModel{
		Keys: bson.D{
			{"parsed.extensions.basic_constraints.is_ca", 1},
			{"parsed.subject_dn", 1},
		},
		Options: options.Index().
			SetPartialFilterExpression(bson.D{
				{"parsed.extensions.basic_constraints.is_ca", true},
				{"valid", true},
			}),
	}
	_, err = allCerts.Indexes().CreateOne(context.TODO(), immIndex)
	if err != nil {
		return Database{}, err
	}

	preventDupsIP := mongo.IndexModel{
		Keys: bson.M{
			"ip": 1,
		}, Options: options.Index().
			SetUnique(true).
			SetPartialFilterExpression(bson.M{
				"ip": bson.M{
					"$exists": true,
				},
			}),
	}
	_, err = scanInfo.Indexes().CreateOne(context.TODO(), preventDupsIP)
	if err != nil {
		return Database{}, err
	}
	preventDupsDomain := mongo.IndexModel{
		Keys: bson.M{
			"domain": 1,
		}, Options: options.Index().
			SetUnique(true).
			SetPartialFilterExpression(bson.M{
				"domain": bson.M{
					"$exists": true,
				},
			}),
	}
	_, err = scanInfo.Indexes().CreateOne(context.TODO(), preventDupsDomain)
	if err != nil {
		return Database{}, err
	}
	// Index for transvalid sites
	transvalidSites := mongo.IndexModel{
		Keys: bson.M{
			"transvalid": 1,
		}, Options: options.Index().
			SetPartialFilterExpression(bson.M{
				"transvalid": true,
			}),
	}
	_, err = scanInfo.Indexes().CreateOne(context.TODO(), transvalidSites)
	if err != nil {
		return Database{}, err
	}
	return Database{
		client:   client,
		certDB:   db,
		ScanInfo: scanInfo,
		AllCerts: allCerts,
	}, nil
}

func (d *Database) Close() error {
	ctx := context.Background()
	d.FlushCertInfo()
	return d.client.Disconnect(ctx)
}

// expects a line of json
// Buffers the insert
func (d *Database) AddCertInfo(line []byte) error {
	var err error = nil
	if len(d.resultBuffer) == BUFFER_SIZE {
		err = d.FlushCertInfo()
	}
	var data bson.M
	bson.UnmarshalExtJSON(line, true, &data)
	d.resultBuffer = append(d.resultBuffer, data)
	return err
}

func (d *Database) InsertCert(cert interface{}, getID bool) (interface{}, error) {
	var id interface{}
	insert_res, err := d.AllCerts.InsertOne(
		context.TODO(),
		cert,
	)
	if err != nil {
		rawCert := cert.(primitive.M)["raw"].(string)
		fingerprint := cert.(primitive.M)["parsed"].(primitive.M)["fingerprint_sha256"]
		if getID && mongo.IsDuplicateKeyError(err) {
			find_result := d.AllCerts.FindOne(
				context.TODO(),
				// Search by unique key
				bson.M{
					"parsed.fingerprint_sha256": fingerprint,
				},
				options.FindOne().SetProjection(bson.M{"_id": 1, "raw": 1}),
			)
			var doc bson.M
			err = find_result.Decode(&doc)
			if err != nil {
				return nil, err
			}
			id = doc["_id"]
			// Check if collision
			if doc["raw"].(string) != rawCert {
				// Report fingerprint collision
				outputFile, err := os.OpenFile("output/collisions",
					os.O_APPEND|os.O_CREATE|os.O_WRONLY,
					0644,
				)
				if err != nil {
					return nil, err
				}
				defer outputFile.Close()
				outputFile.WriteString(rawCert + "\n")
				return nil, fmt.Errorf("fingerprint collision: %v", rawCert)
			}
		} else {
			return nil, err
		}
	} else {
		id = insert_res.InsertedID
	}
	return id, nil
}

func (d *Database) FlushCertInfo() error {
	var err error = nil
	for i := range d.resultBuffer {
		entry := d.resultBuffer[i]
		// Check if key data exists
		if data_i, ok := entry["data"]; ok {
			if data, ok := data_i.(primitive.M); ok {
				// Check if TLS exists
				if tls_i, ok := data["tls"]; ok {
					if tls, ok := tls_i.(primitive.M); ok {
						// Check is result exists
						if res_i, ok := tls["result"]; ok {
							if res, ok := res_i.(primitive.M); ok {
								// Check is handshake_log exists
								if hd_i, ok := res["handshake_log"]; ok {
									if hd, ok := hd_i.(primitive.M); ok {
										// Check is server_certificates exists
										if sc_i, ok := hd["server_certificates"]; ok {
											if sc, ok := sc_i.(primitive.M); ok {
												if siteCert, ok := sc["certificate"]; ok {
													id, err := d.InsertCert(siteCert, true)
													if err != nil {
														return err
													}
													sc["certificate"] = id
												} else {
													return errors.Errorf("certificate not present: %v", sc)
												}
												if chain_i, ok := sc["chain"]; ok {
													if chain, ok := chain_i.(primitive.A); ok {
														var ids []interface{}
														for l := range chain {
															id, err := d.InsertCert(chain[l], true)
															if err != nil {
																return err
															}
															ids = append(ids, id)
														}
														sc["chain"] = ids
													}
												}
											} else {
												return errors.Errorf("server_certificates not a map: %v", sc_i)
											}
										} else {
											return errors.Errorf("server_certificates not in: %v", hd)
										}
									} else {
										return errors.Errorf("handshake_log not a map: %v", hd_i)
									}
								} else {
									return errors.Errorf("handshake_log not in: %v", res)
								}
							} else {
								return errors.Errorf("result not a map: %v", res_i)
							}
						} else {
							return errors.Errorf("result not in: %v", tls)
						}
					} else {
						return errors.Errorf("tls not a map: %v", tls_i)
					}
				} else {
					return errors.Errorf("tls not in: %v", data)
				}
			} else {
				return errors.Errorf("data not a map: %T", data_i)
			}
		} else {
			return errors.Errorf("data not in: %v", entry)
		}
	}

	// I don't know how to convert to interface so recreate the list
	var docs []interface{}
	for i := range d.resultBuffer {
		docs = append(docs, d.resultBuffer[i])
	}
	if len(d.resultBuffer) > 0 {
		_, err = d.ScanInfo.InsertMany(
			context.TODO(),
			docs,
			options.InsertMany().SetOrdered(false),
		)
		d.resultBuffer = nil
	}
	return err
}

func (d *Database) GetUntransvalidatedCerts() (*mongo.Cursor, error) {
	query := bson.M{
		"valid": false,
		"transvalid": bson.M{
			"$exists": false,
		},
	}

	return d.ScanInfo.Find(context.TODO(), query, options.Find().SetBatchSize(1000))
}

func (d *Database) GetUnvalidatedCerts() (*mongo.Cursor, error) {
	query := bson.M{
		"valid": bson.M{
			"$exists": false,
		},
	}

	return d.ScanInfo.Find(context.TODO(), query, options.Find().SetBatchSize(1000))
}

func (d *Database) GetCertByID(id primitive.ObjectID) (bson.M, error) {
	res := d.AllCerts.FindOne(context.TODO(), bson.M{
		"_id": id,
	})
	var cert bson.M
	err := res.Decode(&cert)
	return cert, err
}

func (d *Database) GetCertsByIDs(ids []primitive.ObjectID) ([]bson.M, error) {
	var idArray primitive.A
	for _, id := range ids {
		idArray = append(idArray, id)
	}
	res, err := d.AllCerts.Find(context.TODO(), bson.M{
		"_id": bson.M{
			"$in": idArray,
		},
	})
	if err != nil {
		return nil, err
	}
	var certs []bson.M
	if err = res.All(context.TODO(), &certs); err != nil {
		return nil, err
	}
	return certs, nil
}

func (d *Database) SetScanValidation(id primitive.ObjectID, isValid bool, transvalid bool) error {
	setUpdates := bson.M{
		"valid": isValid,
	}
	if transvalid {
		setUpdates["transvalid"] = isValid
	}
	updates := bson.M{
		"$set": setUpdates,
	}

	_, err := d.ScanInfo.UpdateByID(context.TODO(),
		id,
		updates,
	)
	return err
}

func (d *Database) SetCertValidation(id primitive.ObjectID, validRoots map[string]struct{}) error {
	isValid := false
	if len(validRoots) > 0 {
		isValid = true
	}
	var validRootsNames bson.A = bson.A{}
	for name := range validRoots {
		validRootsNames = append(validRootsNames, name)
	}
	updates := bson.A{bson.M{
		"$set": bson.M{
			"valid": bson.M{
				"$or": bson.A{
					isValid, "$valid",
				},
			},
		},
	}}

	_, err := d.AllCerts.UpdateByID(context.TODO(),
		id,
		updates,
	)
	if err != nil {
		return err
	}
	updates2 := bson.M{
		"$addToSet": bson.M{
			"validRoots": bson.M{
				"$each": validRootsNames,
			},
		},
	}
	_, err = d.AllCerts.UpdateByID(context.TODO(),
		id,
		updates2,
	)
	return err
}
