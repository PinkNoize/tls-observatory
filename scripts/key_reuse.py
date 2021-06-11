from observatory_utils import get_creds, print_results
import pymongo

def get_ca_duplicate_keys(allCerts):
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
                    "_id": "$parsed.subject_key_info",
                    "count": {
                        "$sum": 1,
                    },
                    "ids": {
                        "$push": "$_id",
                    }
                }
            },
            {
                "$match": {
                    "_id": {
                        "$ne": None
                    },
                    "count": {
                        "$gt": 1
                    },
                }
            },
            {
                "$project": {
                    "key_info": "$_id",
                    "ids": 1,
                    "_id" : 0,
                    "count": 1,
                }
            }
        ],
    allowDiskUse=True)

    for result in cursor:
        res_str = f"fingerprint_sha256: {result['key_info']['fingerprint_sha256']}\n"
        res_str += f"\tCount: {result['count']}\n"
        res_str += f"\tAlgo: {result['key_info']['key_algorithm']['name']}\n"
        for id in result['ids']:
            res_str += f"\tID: {id}\n"
            cert = allCerts.find_one({'_id': id})
            try:
                res_str += f"\t\tSubject: {cert['parsed']['subject_dn']}\n"
                res_str += f"\t\tIssuer: {cert['parsed']['issuer_dn']}\n"
                res_str += f"\t\tValidity: {cert['parsed']['validity']['start']} - {cert['parsed']['validity']['end']}\n"
                res_str += f"\t\tValid Roots: {cert['validRoots']}\n"
            except KeyError:
                pass
        yield res_str
    return


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
    print_results("Duplicate Keys", get_ca_duplicate_keys(allCerts))

if __name__ == "__main__":
    main()