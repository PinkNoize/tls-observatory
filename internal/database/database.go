package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const CREDS_FILE = "output/dbcreds.json"
const CERT_DB = "tls-observatory"
const CERTINFO_COL = "certInfo"

const BUFFER_SIZE = 650

type Database struct {
	client     *mongo.Client
	certDB     *mongo.Database
	certInfo   *mongo.Collection
	certBuffer []interface{}
}

type databaseConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hostname string `json:"hostname"`
	Dbname   string `json:"dbname"`
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
	self := New(client)
	return &self, nil
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
	self := New(client)
	return &self, nil
}

func New(client *mongo.Client) Database {
	db := client.Database(CERT_DB)
	return Database{
		client:   client,
		certDB:   db,
		certInfo: db.Collection(CERTINFO_COL),
	}
}

func (d *Database) Close() error {
	ctx := context.Background()
	d.FlushCertInfo()
	return d.client.Disconnect(ctx)
}

// expects a line of json
// Buffers the insert
func (d *Database) AddCertInfo(line []byte) error {
	var doc interface{}
	err := bson.UnmarshalExtJSON(line, true, &doc)
	if err != nil {
		return err
	}
	if len(d.certBuffer) == BUFFER_SIZE {
		d.FlushCertInfo()
	}
	d.certBuffer = append(d.certBuffer, doc)
	return err
}

func (d *Database) FlushCertInfo() error {
	var err error = nil
	if len(d.certBuffer) > 0 {
		_, err = d.certInfo.InsertMany(
			context.TODO(),
			d.certBuffer,
			options.InsertMany().SetOrdered(false),
		)
		d.certBuffer = nil
	}
	return err
}
