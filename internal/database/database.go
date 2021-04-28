package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const CREDS_FILE = "output/dbcreds.json"
const CERT_DB = "tls-observatory"
const CERTINFO_COL = "certInfo"
const ALLCERT_COL = "allCerts"

const BUFFER_SIZE = 650

type Database struct {
	client       *mongo.Client
	certDB       *mongo.Database
	certInfo     *mongo.Collection
	allCerts     *mongo.Collection
	resultBuffer []bson.M
}

type databaseConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hostname string `json:"hostname"`
	Dbname   string `json:"dbname"`
}

type ZGrabResponse struct {
	Data *struct {
		TLS *struct {
			Status string `json:"status"`
			Error  string `json:"error"`
			Result *struct {
				HandshakeLog *struct {
					ServerCertificates *struct {
						Certificate *json.RawMessage   `json:"certificate"`
						Chain       *[]json.RawMessage `json:"chain"`
					} `json:"server_certificates"`
				} `json:"handshake_log"`
			} `json:"result"`
		} `json:"tls"`
	} `json:"data"`
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
	preventDups := mongo.IndexModel{
		Keys: bson.M{
			"raw": 1,
		}, Options: options.Index().SetUnique(true),
	}
	_, err := allCerts.Indexes().CreateOne(context.TODO(), preventDups)
	if err != nil {
		return Database{}, err
	}
	return Database{
		client:   client,
		certDB:   db,
		certInfo: db.Collection(CERTINFO_COL),
		allCerts: allCerts,
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

func (d *Database) insertCert(cert interface{}) (interface{}, error) {
	var id interface{}
	insert_res, err := d.allCerts.InsertOne(
		context.TODO(),
		cert,
	)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			find_result := d.allCerts.FindOne(
				context.TODO(),
				bson.M{
					"raw": cert.(map[string]interface{})["raw"],
				},
				options.FindOne().SetProjection(bson.M{"_id": 1}),
			)
			var doc bson.M
			err = find_result.Decode(&doc)
			if err != nil {
				return nil, err
			}
			id = doc["_id"]
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
			if data, ok := data_i.(map[string]interface{}); ok {
				// Check if TLS exists
				if tls_i, ok := data["tls"]; ok {
					if tls, ok := tls_i.(map[string]interface{}); ok {
						// Check is result exists
						if res_i, ok := tls["result"]; ok {
							if res, ok := res_i.(map[string]interface{}); ok {
								// Check is handshake_log exists
								if hd_i, ok := res["handshake_log"]; ok {
									if hd, ok := hd_i.(map[string]interface{}); ok {
										// Check is server_certificates exists
										if sc_i, ok := hd["server_certificates"]; ok {
											if sc, ok := sc_i.(map[string]interface{}); ok {
												if siteCert, ok := sc["certificate"]; ok {
													id, err := d.insertCert(siteCert)
													if err != nil {
														return err
													}
													sc["certificate"] = id
												}
												if chain_i, ok := sc["chain"]; ok {
													if chain, ok := chain_i.(primitive.A); ok {
														var ids []interface{}
														for l := range chain {
															id, err := d.insertCert(chain[l])
															if err != nil {
																return err
															}
															ids = append(ids, id)
														}
														sc["chain"] = ids
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	// I don't know how to convert to interface so recreate the list
	var docs []interface{}
	for i := range d.resultBuffer {
		docs = append(docs, d.resultBuffer[i])
	}
	if len(d.resultBuffer) > 0 {
		_, err = d.certInfo.InsertMany(
			context.TODO(),
			docs,
			options.InsertMany().SetOrdered(false),
		)
		d.resultBuffer = nil
	}
	return err
}
