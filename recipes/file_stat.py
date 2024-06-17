__author__ = 'https://github.com/password123456/'
__date__ = '2024.06.17'

import os
import stat
from datetime import datetime


def format_mode(mode):
    return oct(mode)[-3:]


def file_type(mode):
    if stat.S_ISREG(mode):
        return "regular file"
    elif stat.S_ISDIR(mode):
        return "directory"
    elif stat.S_ISLNK(mode):
        return "symbolic link"
    elif stat.S_ISCHR(mode):
        return "character special file"
    elif stat.S_ISBLK(mode):
        return "block special file"
    elif stat.S_ISFIFO(mode):
        return "FIFO"
    elif stat.S_ISSOCK(mode):
        return "socket"
    else:
        return "unknown"


def format_time(epoch_time):
    dt = datetime.fromtimestamp(epoch_time)
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f %z')


def get_file_info(filepath):
    stat_info = os.stat(filepath)
    mode = format_mode(stat_info.st_mode)
    f_type = file_type(stat_info.st_mode)
    size = stat_info.st_size
    access_time = format_time(stat_info.st_atime)
    modify_time = format_time(stat_info.st_mtime)
    change_time = format_time(stat_info.st_ctime)

    result = [
        f"File: {filepath}",
        f"Size: {size}  {f_type}",
        f"Access: {access_time}",
        f"Modify: {modify_time}",
        f"Change: {change_time}"
    ]
    return "\n".join(result)


def file_stat(option, filepath):
    if not os.path.exists(filepath):
        return f"cannot stat ‘{filepath}’: No such file or directory"

    if not os.access(filepath, os.R_OK):
        return f"cannot stat ‘{filepath}’: Permission denied"

    try:
        if option == 'octal':
            stat_info = os.stat(filepath)
            return format_mode(stat_info.st_mode)
        elif option == 'all':
            return get_file_info(filepath)
        else:
            return f"Invalid option: {option}"
    except PermissionError:
        return f"cannot stat ‘{filepath}’: Permission denied"
    except Exception as e:
        return f"cannot stat ‘{filepath}’: {str(e)}"


print(file_stat('octal', '/etc/passwd'))
print(file_stat('all', '/etc/passwd'))

"""
644

File: /etc/passwd
Size: 8160  regular file
Access: 2022-10-18 20:36:21.000000 
Modify: 2022-10-18 20:36:21.000000 
Change: 2022-11-28 00:26:03.065074 
"""
