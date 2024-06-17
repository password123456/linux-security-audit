__author__ = 'https://github.com/password123456/'
__date__ = '2024.06.17'

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

    perm_str = ""
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


def get_file_info_ls(file_path):
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


def ls_al(filepath):
    result = []

    if not os.path.exists(filepath) and not os.path.islink(filepath):
        return f"ls -al: cannot access '{filepath}': No such file or directory"

    if not os.access(filepath, os.R_OK) and not os.path.islink(filepath):
        return f"ls -al: cannot access '{filepath}': Permission denied"

    try:
        if os.path.isdir(filepath):
            for entry in os.scandir(filepath):
                file_path = os.path.join(filepath, entry.name)
                result.append(get_file_info_ls(file_path))
        elif os.path.isfile(filepath) or os.path.islink(filepath):
            result.append(get_file_info_ls(filepath))
    except PermissionError:
        return f"ls -al: cannot access '{filepath}': Permission denied"
    except Exception as e:
        return f"ls -al: cannot access '{filepath}': {str(e)}"

    return "\n".join(result)


print(ls_al('/etc/passwd'))
print(ls_al('/etc/localtime'))
print(ls_al('/usr/bin/crontab'))
print(ls_al('/usr/bin/at'))
print(ls_al('/usr/bin/write'))
print(ls_al('/System/Library/Templates/Data/Library/Fonts'))

"""
-rw-r--r-- 1 root wheel 8160 Oct 18 20:36 /etc/passwd
lrwxr-xr-x 1 root wheel 36 Feb 04 12:57 /etc/localtime -> /var/db/timezone/zoneinfo/Asia/Seoul
-rwsr-xr-x 1 root wheel 203984 Oct 18 21:36 /usr/bin/crontab
-r-sr-xr-x 2 root wheel 187040 Oct 18 21:36 /usr/bin/at
-r-xr-sr-x 1 root tty 135584 Oct 18 21:36 /usr/bin/write
lrwxr-xr-x 1 root wheel 52 Oct 18 21:36 /System/Library/Templates/Data/Library/Fonts/Arial Unicode.ttf -> /System/Library/Fonts/Supplemental/Arial Unicode.ttf
"""
