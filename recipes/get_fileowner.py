__author__ = 'https://github.com/password123456/'
__date__ = '2024.06.17'

import os
import pwd
import grp


def get_fileowner(filepath):
    try:
        stat_info = os.stat(filepath)
        uid = stat_info.st_uid
        gid = stat_info.st_gid

        try:
            owner = pwd.getpwuid(uid).pw_name
        except KeyError:
            owner = str(uid)

        try:
            group = grp.getgrgid(gid).gr_name
        except KeyError:
            group = str(gid)

        result = f'{owner}:{group}'
        return result

    except FileNotFoundError:
        return f"cannot stat '{filepath}': No such file or directory"
    except PermissionError:
        return f"cannot stat '{filepath}': Permission denied"
    except Exception as e:
        return f"cannot stat '{filepath}': {e}"


print(get_fileowner('/usr/bin/at'))
print(get_fileowner('/usr/bin/write1'))

"""
root:wheel
cannot stat '/usr/bin/write1': No such file or directory
"""
