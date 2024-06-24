__author__ = 'https://github.com/password123456/'
__date__ = '2024.06.21'


def check_weak_password_hash_users():
    result_code = 0
    raw_data = ''
    audit_files = './etc/shadow'
    lookup_hash = {
        "$1$": "MD5",
        "$2$": "blowfish",
        "$2a$": "blowfish",
        "$2y$": "blowfish",
        "$5$": "SHA-256",
        "$6$": "SHA-512",
        "$y$": "yescrypt",
        "$7$": "yescrypt"
    }

    safe_password_hash = ["$6$", "$y$", "$7$"]
    try:
        with open(audit_files, 'r', encoding='utf-8') as f:
            for line in f:
                fields = line.strip().split(':')
                if len(fields) < 2 or not fields[1] or fields[1].startswith(('*', '!')):
                    continue

                hash_prefix = fields[1].split('$')[1] if '$' in fields[1] else ''
                password_hash = lookup_hash.get("$" + hash_prefix + "$", "DES")

                if not fields[1].startswith(tuple(safe_password_hash)):
                    result_code = 1
                    raw_data += f'[vul] {fields[0]}{fields[1][:8]}...{password_hash}...:{":".join(fields[2:])}\n'
                else:
                    raw_data += f'[ok] {fields[0]}:{fields[1][:8]}...{password_hash}....:{":".join(fields[2:])}\n'

            raw_data = f'# cat {audit_files}\n...\n{raw_data}'
    except Exception as error:
        result_code = 3
        raw_data = f'{str(error)}'

    return raw_data, result_code


def main():
    raw_data, result_code = check_weak_password_hash_users()
    print(f'Result Code: {result_code}')
    print(f'Raw Data: \n{raw_data}')


if __name__ == '__main__':
    main()

"""
Result Code: 1
Raw Data: 
# cat ./etc/shadow
...
[ok] root:$6$nzXIn......SHA-512....::0:99999:7:::
[ok] chrony:$6$TxGdY....SHA-512....:19405::::::
[ok] viva:$6$TxGdY.....SHA-512....:19523:1:99999:15:::
[vul] nova1$1$TxGdY.....MD5.....:19523:1:99999:15:::

"""
