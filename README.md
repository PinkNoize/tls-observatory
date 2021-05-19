# TLS Observatory

# Setup

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