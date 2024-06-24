__author__ = 'https://github.com/password123456/'
__date__ = '2024.06.21'


def check_disabled_accounts_passwords():
    raw_data = ''
    result_code = 0
    audit_files = '/etc/passwd'
    shadow_password = '/etc/shadow'

    try:
        shadow_dict = {}
        with open(shadow_password, 'r', encoding='utf-8') as sf:
            for line in sf:
                fields = line.strip().split(':')
                username = fields[0]
                password_hash = fields[1]
                shadow_dict[username] = password_hash

        with open(audit_files, 'r', encoding='utf-8') as pf:
            for line in pf:
                if line.startswith('#'):
                    continue

                fields = line.strip().split(':')
                username = fields[0]
                shell_status = fields[-1].split('/')[-1]

                if username in ['root', 'halt', 'sync', 'shutdown', 'nfsnobody']:
                    continue

                if shell_status in ['nologin', 'false']:
                    password_hash = shadow_dict.get(username, '')
                    if password_hash.startswith('$'):
                        result_code = 1
                        raw_data += f'[vul] {line.strip()} ---> [{shadow_password} >> {password_hash[:8]}....]\n'
                    else:
                        raw_data += f'[ok] {line.strip()}\n'
            raw_data = f'# cat {audit_files}\n...\n{raw_data}'
    except FileNotFoundError as fnf_error:
        result_code = 3
        raw_data = f'File not found: {str(fnf_error)}'
    except Exception as error:
        result_code = 3
        raw_data = f'Error: {str(error)}'

    return raw_data, result_code


def main():
    raw_data, result_code = check_disabled_accounts_passwords()
    print(f'Result Code: {result_code}')
    print(f'Raw Data: \n{raw_data}')


"""
Result Code: 0
Raw Data: 
# cat ./etc/passwd
...
[ok] bin:x:1:1:bin:/bin:/sbin/nologin
[ok] daemon:x:2:2:daemon:/sbin:/sbin/nologin
[ok] adm:x:3:4:adm:/var/adm:/sbin/nologin
[ok] mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
[ok] operator:x:11:0:operator:/root:/sbin/nologin
[ok] nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
[ok] dbus:x:81:81:System message bus:/:/sbin/nologin
[ok] systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
[ok] systemd-resolve:x:193:193:systemd Resolver:/:/sbin/nologin
[ok] tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
[ok] polkitd:x:998:996:User for polkitd:/:/sbin/nologin
[ok] sssd:x:997:994:User for sssd:/:/sbin/nologin
[vul] chrony:x:996:993::/var/lib/chrony:/sbin/nologin ---> [./etc/shadow >> $6$TxGdY....]
[ok] sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
[ok] tcpdump:x:72:72::/:/sbin/nologin
[ok] unbound:x:499:499:Unbound DNS resolver:/etc/unbound:/sbin/nologin
[ok] gluster:x:498:498:GlusterFS daemons:/run/gluster:/sbin/nologin
[ok] rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
[ok] haproxy:x:497:497:haproxy:/var/lib/haproxy:/sbin/nologin
"""
