# Using my data

*This will be added once I find a place for >100GB of files.*

# Collecting your own data

## Start the mongoDB database using Docker
1. Install Docker
2. Change the password in docker-compose.yml
3. Start the mongoDB server
    
    ```
    $ cd tls-observatory
    $ sudo docker-compose up -d
    ```
    This will setup a database that will listen on 127.0.0.1:27017

    NOTE: If you want to stop the database but still keep the data, run `docker-compose stop`.
    
    `docker-compose down` will delete your database.

4. Connect to the server to test
    
    ```
    $ mongo --username root
    ```

## Setup the datasets
```
$ cd tls-observatory
$ go run . download
```

This command will download the Root CA trust stores and some IPv6 datasets. Feel free to Ctrl-C the download after the Root CAs have downloaded unless you plan to use the IPv6 datasets. If you don't plan to use the IPv6 datasets be sure to delete them (`rm -r output/datasets/*`).

After this a directory named `output` should be created. To add more datasets create a directory in `output/datasets` and add files to that directory with domains/IPs. The files can be plaintext, gzip or xz compressed.

## Run the scan
```
$ go run . collectCerts
```

After running this command you will be prompted for the mongodb's hostname, username and password. These will be stored in `output/dbcreds.json` so you only have to type them once. After you can select which datasets you want to enable/disable with the `space` key. If you want to use all of them feel free to skip the menus with `ESC`. This will run for a long time so its recommended to run in a tmux session or another detachable terminal.

## Validate the scan
```
$ go run . validate
```

Run this command to find which certificates are valid. This processes is interruptable and resumable so feel free to Ctrl-C.

After all sites have been checked for validity (meaning that `go run . validate` exited on its own), you can run
```
$ go run . transvalidate
```
to check for transvalid certificates. Once this completes the database is complete.

If you don't have time to check if all certificates are valid/transvalid you can still run the analyses but you will only be querying the data that has been validated.

## Run the Analyses
```
$ python3 scripts/weak_keys.py > weak_keys.out
$ python3 scripts/signing_orgs.py > signing_orgs.out
$ python3 scripts/key_reuse.py > key_reuse.out
$ python3 scripts/important_questions.py > important_questions.out
```

# Analyses

## Weak Key Tests (`scripts/weak_keys.py`)
- Root CA Key Types
  - Counts the key types of all root CAs
  - Found in `count_key_types_root_ca()`

- Root CA RSA Key Sizes
  - Counts the RSA key sizes of all root CAs
  - Found in `count_key_sizes_root_ca()`

- Key Types
  - Counts the key types of all valid certs
  - Found in `count_key_types()`

- RSA Key Sizes
  - Counts the RSA key sizes of all valid certs
  - Found in `count_key_sizes()`

- CA Certificate Key Signatures
  - Counts the signature algorithms used on valid CA certs
  - Found in `count_ca_cert_signature_algo()`

## Signing Organization Tests (`scripts/signing_orgs.py`)
- Root CA Orgs
  - Groups root CA certs by issuer org, counts them and lists their countries
  - Found in `get_root_ca_orgs()`

- CA Orgs
  - Groups valid CA certs by issuer org, counts them and lists their countries
  - Found in `get_ca_orgs()`

## Key Reuse Tests (`scripts/key_reuse.py`)
- Duplicate Keys
  - Finds duplicate keys on different CA certificates and counts them
  - TODO: Check expiration dates to check if key life is begin extended
  - Found in `get_ca_duplicate_keys()`

## Misc Tests (`scripts/important_questions.py`)
- Certificates with Same Signature
  - Finds certificates with the same signature
  - Found in `certs_same_sig()`

- Basic Constraint:CA != Key Usage Sign
  - Finds certs where the is_ca attribute does not match the certificate_sign attribute (Ex. the cert is not a CA cert but has the certificate_sign key usage set)
  - Found in `key_usage_match_ca_check()`

- CA Certs per Country
  - Groups certs by country and counts them
  - Found in `ca_country_stats()`

- TLS Version Stats
  - Groups each scan by the TLS version used when scanning and counts them
  - Found in `tls_version_count()`

- Certs with IPs
  - Finds certs that are valid for either an IPv4 or IPv6 address
  - Found in `find_ip_names()`