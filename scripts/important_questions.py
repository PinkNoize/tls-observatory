from observatory_utils import get_creds, print_results
import pymongo

# Find certs with different fingerprints but same signature
def certs_same_sig(allCerts):
    res = allCerts.aggregate(
    [
        {
            "$match": {
                "valid": True,
            }
        },
        {
            "$group": {
                "_id": "$parsed.signature.value",
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$match": {
                "_id" : {
                    "$ne" : "null"
                },
                "count" : {
                    "$gt": 1
                }
            }
        },
        {
            "$project": {
                "parsed.signature.value": "$_id",
                "_id" : 0,
                "count": 1,
            }
        }
    ],
    allowDiskUse=True)
    return res

# Find certs where the key usage fields don't match basic constraints:CA
# matching fields look like:
def key_usage_match_ca_check(allCerts):
    cursor = allCerts.find({
        'valid': True,
        '$or': [
            {
                'parsed.extensions.basic_constraints.is_ca': True,
                'parsed.extensions.key_usage.certificate_sign': False,
            },
            {
                'parsed.extensions.basic_constraints.is_ca': False,
                'parsed.extensions.key_usage.certificate_sign': True,
            },
        ]
    })
    return cursor

# Count CA certs per country
def ca_country_stats(allCerts):
    res = allCerts.aggregate([
        {
            "$match": {
                "valid": True,
                "parsed.extensions.basic_constraints.is_ca": True
            }
        },
        {
            "$group" : {
                "_id": "$parsed.issuer.country",
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$match": {
                "_id" : {
                    "$ne" : None
                }
            }
        },
        {
            "$project": {
                "country": "$_id",
                "_id" : 0,
                "count": 1,
            }
        }
    ])
    return res

# Find certs with IP addresses as names
def find_ip_names(allCerts):
    # Regex from https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    MATCH_IP = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    res = allCerts.find({
        "parsed.names": {
            "$regex": MATCH_IP,
        },
        "valid": True,
    },
    projection={
            "_id": 1,
            "parsed.names": 1,
        },
    )
    for doc in res:
        names = doc["parsed"]["names"]
        id = doc["_id"]
        yield {"_id": id, "names": names}
    return

def tls_version_count(scanInfo):
    cursor = scanInfo.aggregate([
        {
            "$match": {
                "valid": True,
            }
        },
        {
            "$group" : {
                "_id": "$data.tls.result.handshake_log.server_hello.version.name",
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$match": {
                "_id" : {
                    "$ne" : None
                }
            }
        },
        {
            "$project": {
                "tls_version": "$_id",
                "_id" : 0,
                "count": 1,
            }
        }
    ])
    return cursor

def main():
    creds = get_creds()
    client = pymongo.MongoClient(
        host=creds['hostname'],
        username=creds['username'],
        password=creds['password']
    )
    db=client['tls-observatory']
    scanInfo = db['scanInfo']
    allCerts = db['allCerts']
    print_results("Certificates With Same Signature", certs_same_sig(allCerts))
    print_results("Basic Constraint:CA != Key Usage Sign", key_usage_match_ca_check(allCerts))
    print_results("CA Certs per Country", ca_country_stats(allCerts))
    print_results("TLS Version Stats", tls_version_count(scanInfo))
    print_results("Certs with IPs", find_ip_names(allCerts))

if __name__ == "__main__":
    main()