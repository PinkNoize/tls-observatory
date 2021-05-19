import json

def get_creds():
    with open('./output/dbcreds.json', 'r') as f:
        data = f.read()
    return json.loads(data)

def print_results(title, res_iter):
    header_len = 50
    header = '-'*((header_len-len(title)+2)//2)
    header += f' {title} '
    header += '-'*(header_len - len(header))
    print(header)
    count = 0
    for item in res_iter:
        print(item)
        count += 1
    print(f"Total Items: {count}")
    print('-'*header_len)