from observatory_utils import get_creds, print_results
import pymongo


# Get all orgs with a CA cert
def get_ca_orgs(allCerts):
    cursor = allCerts.aggregate(
    [
        {
            "$match": {
                "valid": True,
                "parsed.extensions.basic_constraints.is_ca": True,
            }
        },
        {
            "$group": {
                "_id": "$parsed.issuer.organization",
                "count": {
                    "$sum": 1
                },
                "countries": {
                    "$push": "$parsed.issuer.country"
                }
            }
        },
        {
            "$project": {
                "organization": "$_id",
                "countries": {
                    "$reduce": {
                        "input": "$countries",
                        "initialValue": [],
                        "in": {"$setUnion": ["$$value", "$$this"]}
                    }
                },
                "_id" : 0,
                "count": 1,
            }
        }
    ],
    allowDiskUse=True)
    return cursor

# Get all RootCA orgs
def get_root_ca_orgs(allCerts):
    cursor = allCerts.aggregate(
    [
        {
            "$match": {
                "valid": True,
                "isRootCA": True,
            }
        },
        {
            "$group": {
                "_id": "$parsed.issuer.organization",
                "count": {
                    "$sum": 1
                },
                "countries": {
                    "$push": "$parsed.issuer.country"
                }
            }
        },
        {
            "$project": {
                "organization": "$_id",
                "_id" : 0,
                "countries": {
                    "$reduce": {
                        "input": "$countries",
                        "initialValue": [],
                        "in": {"$setUnion": ["$$value", "$$this"]}
                    }
                },
                "count": 1,
            }
        }
    ],
    allowDiskUse=True)
    return cursor

def main():
    creds = get_creds()
    client = pymongo.MongoClient(
        host=creds['hostname'],
        username=creds['username'],
        password=creds['password']
    )
    db=client['tls-observatory']
    certInfo = db['scanInfo']
    allCerts = db['allCerts']
    print_results("Root CA Orgs", get_root_ca_orgs(allCerts))
    print_results("CA Orgs", get_ca_orgs(allCerts))

if __name__ == "__main__":
    main()