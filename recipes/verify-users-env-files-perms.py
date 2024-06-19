__author__ = 'https://github.com/password123456/'
__date__ = '2024.06.19'

import os
import stat
import pwd
import grp
from datetime import datetime


def format_mode(mode):
    if stat.S_ISDIR(mode):
        is_dir = 'd'
    elif stat.S_ISLNK(mode):
        is_dir = 'l'
    else:
        is_dir = '-'

    perms = [
        (stat.S_IRUSR, 'r'), (stat.S_IWUSR, 'w'), (stat.S_IXUSR, 'x', 's', 'S', stat.S_ISUID),
        (stat.S_IRGRP, 'r'), (stat.S_IWGRP, 'w'), (stat.S_IXGRP, 'x', 's', 'S', stat.S_ISGID),
        (stat.S_IROTH, 'r'), (stat.S_IWOTH, 'w'), (stat.S_IXOTH, 'x', 't', 'T', stat.S_ISVTX)
    ]

    perm_str = ''
    for perm in perms:
        if len(perm) == 2:
            perm_str += perm[1] if mode & perm[0] else '-'
        else:
            if mode & perm[0]:
                if mode & perm[4]:
                    perm_str += perm[2] if mode & perm[0] else perm[3]
                else:
                    perm_str += perm[1]
            else:
                perm_str += '-'

    return is_dir + perm_str


def filepath_ls_al(file_path):
    stat_info = os.lstat(file_path)
    mode = format_mode(stat_info.st_mode)
    n_links = stat_info.st_nlink
    owner = pwd.getpwuid(stat_info.st_uid).pw_name
    group = grp.getgrgid(stat_info.st_gid).gr_name
    size = stat_info.st_size
    mtime = datetime.fromtimestamp(stat_info.st_mtime).strftime('%b %d %H:%M')
    name = os.path.abspath(file_path)

    if os.path.islink(file_path):
        target = os.readlink(file_path)
        name = f'{name} -> {target}'

    return f'{mode} {n_links} {owner} {group} {size} {mtime} {name}'


def check_permission(file_path, verify_perm):
    conditions = {
        'others_no_perms': lambda perms: perms[-3:] == '---',
        'others_no_w': lambda perms: perms[-2] == '-',
        'others_no_wx': lambda perms: perms[-2:] == '--'
    }

    if os.path.exists(file_path):
        mode = os.stat(file_path).st_mode
        perms = format_mode(mode)

        if verify_perm in conditions and conditions[verify_perm](perms):
            return '[ok]'
        else:
            return '[vul]'
    return None


def verify_users_env_files_permissions():
    raw_data = ''
    result_code = 0
    password_file = '/etc/passwd'

    check_files = {
        '.ssh': 'others_no_perms',
        '.ssh/id_rsa': 'others_no_perms',
        '.ssh/authorized_keys': 'others_no_perms',
        '.history': 'others_no_wx',
        '.sh_history': 'others_no_wx',
        '.bash_history': 'others_no_wx',
        '.k5login': 'others_no_wx',
        '.profile': 'others_no_w',
        '.cshrc': 'others_no_wx',
        '.kshrc': 'others_no_wx',
        '.bash_profile': 'others_no_wx',
        '.bashrc': 'others_no_wx',
        '.bash_login': 'others_no_wx',
        '.exrc': 'others_no_wx',
        '.netrc': 'others_no_wx',
        '.dtprofile': 'others_no_wx'
    }

    try:
        with open(password_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('#'):
                    continue

                fields = line.strip().split(':')
                shell_status = fields[-1].split('/')[-1]
                if shell_status in ['false', 'nologin', 'null', 'halt', 'sync', 'shutdown']:
                    continue

                if len(fields[5]) == 0 or fields[5] == '/':
                    continue

                for relative_path, verify_perm in check_files.items():
                    file_path = os.path.join(fields[5], relative_path)
                    status = check_permission(file_path, verify_perm)
                    if status:
                        if status == '[vul]':
                            result_code = 1
                        raw_data += f'{status} {filepath_ls_al(file_path)}\n'

    except Exception as error:
        result_code = 3
        raw_data = f'{str(error)}'

    return raw_data, result_code


def main():
    raw_data, result_code = verify_users_env_files_permissions()
    print(f'Result Code: {result_code}')
    print(f'Raw Data: \n{raw_data}')


if __name__ == '__main__':
    main()

"""
Result Code: 1
Raw Data: 
[ok] drwx------ 2 root root 4096 Mar 21 21:14 /root/.ssh
[ok] -rw------- 1 root root 3389 Mar 21 21:13 /root/.ssh/id_rsa
[ok] -rw------- 1 root root 1128 Mar 28 15:25 /root/.ssh/authorized_keys
[ok] -rw------- 1 root root 24842 Jun 19 12:39 /root/.bash_history
[ok] -rw-r--r-- 1 root root 161 Jul 09 19:05 /root/.profile
[ok] -rw-r--r-- 1 root root 3641 Feb 14 22:24 /root/.bashrc
[ok] drwx------ 2 opc opc 4096 Feb 14 21:33 /home/opc/.ssh
[ok] -rw------- 1 opc opc 1126 Mar 28 15:25 /home/opc/.ssh/authorized_keys
[ok] -rw-r--r-- 1 opc opc 807 Jan 07 01:23 /home/opc/.profile
[ok] -rw-r--r-- 1 opc opc 3771 Jan 07 01:23 /home/opc/.bashrc
[ok] drwx------ 2 ubuntu ubuntu 4096 Oct 04 07:16 /home/ubuntu/.ssh
[ok] -rw------- 1 ubuntu ubuntu 1679 Sep 27 10:21 /home/ubuntu/.ssh/id_rsa
[ok] -rw------- 1 ubuntu ubuntu 800 Mar 28 15:25 /home/ubuntu/.ssh/authorized_keys
[ok] -rw------- 1 ubuntu ubuntu 8443 Jun 17 17:43 /home/ubuntu/.bash_history
[vul] -rw-r--rw- 1 ubuntu ubuntu 807 Jan 07 01:23 /home/ubuntu/.profile
[ok] -rw-r--r-- 1 ubuntu ubuntu 4306 Feb 14 22:29 /home/ubuntu/.bashrc
"""
