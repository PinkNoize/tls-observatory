# This script is used to copy CAs to another database
# This is useful if you are running a scan on another machine
# and would like to import the results into a central database later
# This script replaces certs so it may be a lengthy process
#
# Ex. python3 scripts/export_CAs.py <secondary db>
#     This would copy all CA certs from the main db to the secondary db
#     This would make it easier to import the results from the secondary
#     scan using mongorestore

import pymongo
import sys
import getpass
from observatory_utils import get_creds
from tqdm import tqdm

def export_cert(doc, s_scanInfo, s_allCerts):
    exp_cert_id = doc['_id']
    try:
        s_allCerts.insert_one(doc)
        return
    except pymongo.errors.DuplicateKeyError:
        dup = s_allCerts.find_one({
            'raw': doc['raw'],
        })
        if dup is None:
            print(f"Could not find duplicate cert: {doc}")
            return
        dup_id = dup['_id']
        # Get all scans where dup_id is used and replace with the new_id
        cursor = s_scanInfo.find(
            {
                '$or': [
                    {'data.tls.result.handshake_log.server_certificates.certificate': dup_id},
                    {'data.tls.result.handshake_log.server_certificates.chain': dup_id}
                ],
            },
            projection={
                '_id': 1,
                'data.tls.result.handshake_log.server_certificates': 1,
            }
        )
        for use_doc in tqdm(cursor, leave=False):
            server_certs = cursor['data']['tls']['result']['handshake_log']['server_certificates']
            if server_certs['certificate'] == dup_id:
                server_certs['certificate'] = exp_cert_id
            chain = server_certs['chain']
            for i in range(chain):
                if chain[i] == dup_id:
                    chain[i] = exp_cert_id
            s_scanInfo.update_one(
                {
                    '_id': use_doc['_id']
                },
                {
                    '$set': {
                        'data.tls.result.handshake_log.server_certificates.certificate': server_certs['certificate'],
                        'data.tls.result.handshake_log.server_certificates.chain': chain,
                    }
                }
            )

        # Make sure valid certs stay valid
        dup_valid = False
        doc_valid = False
        if 'valid' in doc:
            doc_valid = doc['valid']
        if 'valid' in dup:
            dup_valid = dup['valid']
        if 'valid' in doc or 'valid' in dup:
            doc['valid'] = dup_valid or doc_valid

        # Delete the old cert
        s_allCerts.delete_one({
            '_id': dup_id,
        })
        # try adding the new cert again
        s_allCerts.insert_one(doc)

def export(m_allCerts, s_scanInfo, s_allCerts):
    cursor = m_allCerts.find({
        "parsed.extensions.basic_constraints.is_ca": True,
    })
    for doc in tqdm(cursor):
        export_cert(doc, s_scanInfo, s_allCerts)


def main():
    if len(sys.argv) != 3:
        print(f"{sys.argv[0]} <secondary db domain> <secondary username>")
        sys.exit(0)
    creds = get_creds()
    main_client = pymongo.MongoClient(
        host=creds['hostname'],
        username=creds['username'],
        password=creds['password'],
    )
    # check if connected
    main_client.server_info()

    main_db=main_client['tls-observatory']
    # main_scanInfo = main_db['scanInfo']
    main_allCerts = main_db['allCerts']

    second_host = sys.argv[1]
    second_user = sys.argv[2]

    if second_host == creds['hostname']:
        print(f"Main and Secondary same host: {second_host}")
        sys.exit(1)

    second_password = getpass.getpass('Second DB Password: ')

    second_client = pymongo.MongoClient(
        host=second_host,
        username=second_user,
        password=second_password,
    )
    # check if connected
    second_client.server_info()

    second_db=second_client['tls-observatory']
    second_scanInfo = second_db['scanInfo']
    second_allCerts = second_db['allCerts']
    export(main_allCerts, second_scanInfo, second_allCerts)

    second_client.close()
    main_client.close()

if __name__ == "__main__":
    main()