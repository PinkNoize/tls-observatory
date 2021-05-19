from observatory_utils import get_creds, print_results
import pymongo

# Get Key types and counts
def count_key_types(allCerts):
    cursor = allCerts.aggregate([
        {
            "$match": {
                "valid": True,
            }
        },
        {
            "$group" : {
                "_id": "$parsed.subject_key_info.key_algorithm.name",
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$project": {
                "key_algorithm": "$_id",
                "_id" : 0,
                "count": 1,
            }
        }
    ])
    return cursor

# Get RSA key sizes and counts
def count_rsa_key_sizes(allCerts):
    cursor = allCerts.aggregate([
        {
            "$match": {
                "valid": True,
                "parsed.subject_key_info.key_algorithm.name": "RSA"
            }
        },
        {
            "$group" : {
                "_id": "$parsed.subject_key_info.rsa_public_key.length",
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
                "bitlength": "$_id",
                "_id" : 0,
                "count": 1,
            }
        }
    ])
    return cursor

# Get RootCA Key types and counts
def count_key_types_root_ca(allCerts):
    cursor = allCerts.aggregate([
        {
            "$match": {
                "valid": True,
                "isRootCA": True,
            }
        },
        {
            "$group" : {
                "_id": "$parsed.subject_key_info.key_algorithm.name",
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$project": {
                "key_algorithm": "$_id",
                "_id" : 0,
                "count": 1,
            }
        }
    ])
    return cursor

# Get RootCA RSA key sizes and counts
def count_rsa_key_sizes_root_ca(allCerts):
    cursor = allCerts.aggregate([
        {
            "$match": {
                "valid": True,
                "isRootCA": True,
                "parsed.subject_key_info.key_algorithm.name": "RSA"
            }
        },
        {
            "$group" : {
                "_id": "$parsed.subject_key_info.rsa_public_key.length",
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
                "bitlength": "$_id",
                "_id" : 0,
                "count": 1,
            }
        }
    ])
    return cursor

def count_ca_cert_signature_algo(allCerts):
    cursor = allCerts.aggregate([
        {
            "$match": {
                "valid": True,
                "parsed.extensions.basic_constraints.is_ca": True,
            }
        },
        {
            "$group" : {
                "_id": "$parsed.signature.signature_algorithm.name",
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$project": {
                "signature_algorithm": "$_id",
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
    print_results("Root CA Key Types", count_key_types_root_ca(allCerts))
    print_results("Root CA RSA Key Sizes", count_rsa_key_sizes_root_ca(allCerts))
    print_results("Key Types", count_key_types(allCerts))
    print_results("RSA Key Sizes", count_rsa_key_sizes(allCerts))
    print_results("CA Certificate Key Signatures", count_ca_cert_signature_algo(allCerts))

if __name__ == "__main__":
    main()