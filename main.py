__author__ = 'password123456'
__date__ = '2024.08.06'
__version__ = '1.0.1'
__status__ = 'Production'

import os
import sys
import socket
import struct
import platform
import subprocess
import re
import fcntl
import stat
import pwd
import grp
from datetime import datetime, timedelta


class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Orange = '\033[38;5;208m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class SystemMetadata:
    def __init__(self):
        self.auditor = None
        self.hostname = None
        self.os_name = None
        self.os_version = None
        self.os_id = None
        self.os_arch = None
        self.ip_address = None
        self.mac_address = None

    def initialize(self):
        os_version, os_id, os_name = get_os_release()
        self.auditor = f'{__author__}'
        self.hostname = socket.gethostname()
        self.os_name = os_name
        self.os_version = os_version
        self.os_id = os_id
        self.os_arch = get_os_architecture()
        self.ip_address = get_ip_addresses()
        self.mac_address = get_mac_addresses()

    def get_system_info(self):
        if not self.auditor:
            self.initialize()

        return {
            'auditor': self.auditor,
            'target': self.hostname,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'os_id': self.os_id,
            'os_architecture': self.os_arch,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
        }


def catch_try_error(error, func_name):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback_details = {
        'filename': os.path.realpath(__file__),
        'line_number': exc_traceback.tb_lineno,
        'func_name': func_name,
        'exception': str(error)
    }
    message = (
        f'{traceback_details["filename"]}\n'
        f' - [func]: {traceback_details["func_name"]}\n'
        f' - [line_num]: {traceback_details["line_number"]}\n'
        f' - [exception]: {traceback_details["exception"]}\n'
    )
    return message


""" Get Systeminfo """


def get_os_release():
    # Red Hat Enterprise Linux, Rocky Linux, Amazon Linux, Ubuntu
    os_info = {}
    if os.path.isfile('/etc/os-release'):
        with open('/etc/os-release', 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line.lower().startswith('version_id='):
                    os_info['version_id'] = line.split('=')[1].strip('"')
                if line.lower().startswith('id='):
                    os_info['id'] = line.split('=')[1].strip('"')
                if line.lower().startswith('pretty_name='):
                    os_info['display_name'] = line.split('=')[1].strip('"')
    else:
        os_info['version_id'] = 'Unknown'
        os_info['id'] = 'Unknown'
        os_info['display_name'] = 'Unknown'
    return os_info['version_id'], os_info['id'], os_info['display_name']


def get_os_architecture():
    result = platform.machine()
    if result:
        return result
    else:
        return 'Unknown'


def get_hostname():
    return socket.gethostname()


def get_ip_addresses():
    ip_addresses = {}
    interfaces = socket.if_nameindex()
    for interface in interfaces:
        ifname = interface[1]
        if ifname == 'lo':
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_address = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x8915,
                struct.pack('256s', ifname.encode('utf-8')[:15])
            )[20:24])
            ip_addresses[ifname] = ip_address
        except IOError:
            ip_addresses[ifname] = 'N/A'
    return ', '.join([f"[{iface}] {ip}" for iface, ip in ip_addresses.items()])


def get_mac_addresses():
    mac_addresses = {}
    interfaces = socket.if_nameindex()
    for interface in interfaces:
        ifname = interface[1]
        if ifname == 'lo':
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            mac_address = ':'.join(['%02x' % b for b in fcntl.ioctl(
                sock.fileno(),
                0x8927,
                struct.pack('256s', ifname.encode('utf-8')[:15])
            )[18:24]])
            mac_addresses[ifname] = mac_address
        except IOError:
            mac_addresses[ifname] = 'N/A'
    return ', '.join([f"[{iface}] {mac}" for iface, mac in mac_addresses.items()])


def log_contents(time, item, title, result, result_code, raw_data):
    system_info = SystemMetadata()
    log_data = {
        'datetime': time,
        **system_info.get_system_info(),
        'item_no': item,
        'item_title': title,
        'result': result,
        'result_code': result_code,
        'raw_data': raw_data
    }
    return log_data


def export_result(logfile, log_data):
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write('  <items>\n')
        f.write(f'\t<status>ok</status>\n')
        for key, value in log_data.items():
            if key == 'raw_data':
                f.write(f'\t<{key}>\n\t  <![CDATA[\n{value}\n\t  ]]>\n\t</{key}>\n')
            else:
                f.write(f'\t<{key}>{value}</{key}>\n')
        f.write('  </items>\n')


def wrapping_log(logfile):
    with open(logfile, 'r', encoding='utf-8') as f:
        contents = f.read()

    with open(logfile, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<results>\n')
        f.write(f'{contents}')
        f.write('</results>\n')


def check_logfile(logfile):
    if os.path.exists(logfile):
        os.remove(logfile)


def verify_sudo_privileges():
    if 'SUDO_UID' in os.environ:
        return True
    else:
        return False


def error_sudo_privileges(logfile):
    item_no = '(error) 7749'
    item_title = 'Not enough privileges to run'
    result = 'error'
    result_code = 3
    raw_data = (f'- [run ]: {os.path.realpath(__file__)}\n'
                f'- [func]: {error_sudo_privileges.__name__}\n'
                f'- [exception]: This tool requires `sudo` privileges. Run with `sudo`')
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, result, result_code, raw_data)

    with open(logfile, 'a', encoding='utf-8') as f:
        f.write('  <items>\n')
        f.write(f'\t<status>error</status>\n')
        for key, value in log_data.items():
            if key == 'raw_data':
                f.write(f'\t<{key}>\n\t  <![CDATA[\n{value}\n\t  ]]>\n\t</{key}>\n')
            else:
                f.write(f'\t<{key}>{value}</{key}>\n')
        f.write('  </items>\n')


def error_commands_check(logfile, result_data):
    item_no = '(error) 7120'
    item_title = 'Requires commands that do not exist on this system.'
    result = 'error'
    result_code = 3
    raw_data = (f'- [run ]: {os.path.realpath(__file__)}\n'
                f'- [func]: {error_commands_check.__name__}\n'
                f'- [exception]: This script requires following commands - {result_data}')
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, result, result_code, raw_data)

    with open(logfile, 'a', encoding='utf-8') as f:
        f.write('  <items>\n')
        f.write(f'\t<status>error</status>\n')
        for key, value in log_data.items():
            if key == 'raw_data':
                f.write(f'\t<{key}>\n\t  <![CDATA[\n{value}\t  ]]>\n\t</{key}>\n')
            else:
                f.write(f'\t<{key}>{value}</{key}>\n')
        f.write('  </items>\n')


def logo():
    print(f'{Bcolors.Green} ===========================================================')
    print(f'\t\tLinux Security Audit Tool{Bcolors.Endc} {__version__} ({__date__})')
    print(f'\t\t\t\t{Bcolors.Green}by{Bcolors.Endc} {__author__} ')
    print(f'{Bcolors.Green} =========================================================== {Bcolors.Endc}')


""" Common Functions """


def get_result(result_code):
    result_map = {
        0: 'pass',
        1: 'fault',
        2: 'manual',
        3: 'error'
    }
    return result_map.get(result_code, 'unknown')


def show_result(item_no, item_title, result_code):
    if result_code == 'pass':
        result = f'  [{Bcolors.Green}pass{Bcolors.Endc}]  '
    elif result_code == 'fault':
        result = f'  [{Bcolors.Red}fault{Bcolors.Endc}] '
    elif result_code == 'manual':
        result = f'  [{Bcolors.Yellow}manual{Bcolors.Endc}] '
    elif result_code == 'error':
        result = f'  [{Bcolors.Orange}error{Bcolors.Endc}] '
    else:
        result = '[unknown]'
    print(f'{result}{item_no} : {item_title}')


def verify_required_commands():
    required_commands = ['systemctl', 'ss', 'find']
    results = []

    for cmd in required_commands:
        try:
            subprocess.run([cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except FileNotFoundError:
            results.append(cmd)
        except subprocess.CalledProcessError:
            results.append(cmd)

    if results:
        return False, required_commands
    else:
        return True, []


def grep_search_pattern(source, is_file, is_single_search, search_type, search_pattern, match_group):
    sp_value = None
    line_numbers = []
    sp_value_context_with_line_num = ''
    try:
        if is_file:
            with open(source, 'r', encoding='utf-8') as f:
                file_content = f.readlines()
        else:
            file_content = source.splitlines(True)

        for i, line in enumerate(file_content):
            if line.startswith('#') or len(line.strip()) == 0:
                continue

            if search_type == 'match':
                match = search_pattern.match(line.strip())
            elif search_type == 'search':
                match = search_pattern.search(line.strip())
            else:
                match = search_pattern.match(line.strip())

            if match:
                sp_value = match.group(match_group)

                if is_single_search:
                    start_line = max(0, i - 2)
                    end_line = min(len(file_content), i + 3)
                    context_lines = file_content[start_line:end_line]

                    sp_value_context_with_line_num = ''
                    for idx, context_line in enumerate(context_lines):
                        sp_value_context_with_line_num += f'{start_line + idx + 1}: {context_line}'
                    line_numbers = [i + 1]
                    break
                else:
                    line_numbers.append(i + 1)
                    sp_value_context_with_line_num += f'{i + 1}: {line}'

        line_numbers = ','.join(map(str, line_numbers))
        return sp_value, sp_value_context_with_line_num, line_numbers, file_content
    except FileNotFoundError:
        return None, '', None, None


def filepath_ls_al(file_path):
    try:
        stat_info = os.lstat(file_path)
        mode = get_permission_string(stat_info.st_mode)
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
    except FileNotFoundError:
        return None


def get_permission_string(mode):
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


def filepath_get_owner_group(file_path):
    try:
        stat_info = os.lstat(file_path)
        owner = pwd.getpwuid(stat_info.st_uid).pw_name
        group = grp.getgrgid(stat_info.st_gid).gr_name
        return f'{owner}:{group}'
    except FileNotFoundError:
        return None


def filepath_get_perms_value(filepath):
    try:
        mode = os.stat(filepath).st_mode
        return int(oct(stat.S_IMODE(mode))[2:])
    except FileNotFoundError:
        return None


def filepath_check_perms(file_path, valid_perms):
    if os.path.exists(file_path):
        ret_perms_value = filepath_get_perms_value(file_path)
        if ret_perms_value is not None:
            if ret_perms_value in valid_perms:
                return '[ok]'
            else:
                return '[vul]'
    return None


def check_service_info(service_names):
    services_info = {}
    for service_name in service_names:
        service_info = {'enable_status': '', 'active_status': '', 'run_pid': '', 'binding_info': ''}

        try:
            is_enabled_output = subprocess.check_output(['systemctl', 'is-enabled', service_name], stderr=subprocess.PIPE)
            service_info['enable_status'] = 'enabled' if is_enabled_output.decode('utf-8').strip() == 'enabled' else 'disabled'
        except subprocess.CalledProcessError:
            service_info['enable_status'] = 'disabled'

        try:
            is_active_output = subprocess.check_output(['systemctl', 'is-active', service_name], stderr=subprocess.PIPE)
            if is_active_output.decode('utf-8').strip() == 'active':
                service_info['active_status'] = 'active'
                status_output = subprocess.check_output(['systemctl', 'status', service_name], stderr=subprocess.PIPE)
                status_lines = status_output.decode('utf-8').splitlines()

                search_active_status = re.compile(r'Active:\s+(.*?)\s*$')
                search_running_pid = re.compile(r'Main PID:\s+(\d+)')

                for line in status_lines:
                    if 'Active:' in line:
                        active_match = search_active_status.search(line)
                        if active_match:
                            service_info['active_status'] = active_match.group(1)

                    pid_match = search_running_pid.search(line)
                    if pid_match:
                        service_info['run_pid'] = str(pid_match.group(1))

                if service_info['run_pid']:
                    try:
                        ss_output = subprocess.check_output(['ss', '-plntu'], stderr=subprocess.PIPE)
                        ss_lines = ss_output.decode('utf-8').splitlines()
                        pid_regex = re.compile(rf'\b{service_info["run_pid"]}\b')
                        binding_info = []
                        for line in ss_lines:
                            if pid_regex.search(line):
                                parts = re.split(r'\s+', line.strip())
                                if len(parts) >= 6:
                                    binding_info.append(f"{parts[0]}|{parts[4]}|{parts[6]}")
                        service_info['binding_info'] = '\n'.join(binding_info) if binding_info else 'No Listening Port'
                    except subprocess.CalledProcessError as error:
                        service_info['binding_info'] = f'[Error] fetching listening ports: {error.stderr.decode("utf-8").strip()}'
                    except FileNotFoundError:
                        service_info['binding_info'] = '[Error] fetching listening ports: ss command not found'
            else:
                service_info['active_status'] = 'inactive'
                service_info['run_pid'] = 'NULL'
                service_info['binding_info'] = 'NULL'
        except subprocess.CalledProcessError:
            service_info['active_status'] = 'inactive'
            service_info['run_pid'] = 'NULL'
            service_info['binding_info'] = 'NULL'

        services_info[service_name] = service_info
    return services_info


def subprocess_cmd_execute(cmd):
    try:
        result = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
        return '[ok]', result
    except subprocess.CalledProcessError as error:
        return '[error]', error.output
    except FileNotFoundError:
        return '[error]', f'-bash: {cmd[0]}: command not found'


def get_current_sshd_config():
    cmd = ['sshd', '-T', '-C', 'user=root', '-C', 'addr=127.0.0.1']
    try:
        result = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
        return '[ok]', cmd, result
    except Exception as error:
        return '[error]', None, error


"""START AUDIT ITEMS"""


def a161(logfile):
    item_no = '1.6.1'
    item_title = 'Ensure system wide crypto policy is not set to legacy'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/crypto-policies/config'
    regex_pattern = re.compile(r'^[ \t]*(\bLEGACY\b)', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                result_code = 1
                raw_data += (f'[vul] Found: {files_to_check}\n'
                             f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                             f'near at line: {ret_sp_value_context_num}\n\n'
                             f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[ok] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a162(logfile):
    item_no = '1.6.2'
    item_title = 'Ensure system wide crypto policy disables sha1 hash and signature support'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/crypto-policies/state/CURRENT.pol'
    regex_type = 'match'
    regex_match = 0
    is_vulnerable_values = []
    is_vulnerable = 0
    regex_patterns_dict = {
        'regex_hash_sign': r'^[ \t]*(hash|sign)[ \t]*=[ \t]*([^\n\r#]+)?-sha1\b',
        'regex_sha1_in_certs': r'^[ \t]*sha1_in_certs[ \t]*=[ \t]*(0|1)$'
    }

    if os.path.exists(files_to_check):
        for key, value in regex_patterns_dict.items():
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    if key == 'regex_hash_sign':
                        ret_sp_value_items = ret_sp_value.split('=')[1].strip().split()
                        for item in ret_sp_value_items:
                            if item.lower().endswith('-sha1'):
                                is_vulnerable_values.append(item)
                        is_vulnerable += 1
                        raw_data += (f'[vul] Found: {files_to_check}\n'
                                     f'- found: {regex_pattern.pattern} --> `{",".join(is_vulnerable_values)}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
                    else:
                        ret_sp_value = ret_sp_value.split('=')[1].strip()
                        if int(ret_sp_value) == 1:
                            is_vulnerable += 1
                            raw_data += (f'[vul] Found: {files_to_check}\n'
                                         f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                         f'near at line: {ret_sp_value_context_num}\n\n'
                                         f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 0
                    raw_data += (f'[ok] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    if is_vulnerable == 0:
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a163(logfile):
    item_no = '1.6.3'
    item_title = 'Ensure system wide crypto policy disables cbc for ssh'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/crypto-policies/state/CURRENT.pol'
    regex_type = 'match'
    regex_match = 0
    is_vulnerable_values = []
    is_not_vulnerable = 0
    regex_patterns_dict = {
        'regex_cbc_general': r'^[ \t]*cipher[ \t]*=[ \t]*([^#\n\r]+)?-CBC\b',
        'regex_cbc_ssh': r'^[ \t]*cipher@(lib|open)ssh(-server|-client)?[ \t]*=[ \t]*([^#\n\r]+)?-CBC\b'
    }

    if os.path.exists(files_to_check):
        for key, value in regex_patterns_dict.items():
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    ret_sp_value_items = ret_sp_value.split('=')[1].strip().split()
                    for item in ret_sp_value_items:
                        if item.lower().endswith('-cbc'):
                            is_vulnerable_values.append(item)

                    raw_data += (f'[vul] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `{",".join(is_vulnerable_values)}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
                else:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a164(logfile):
    item_no = '1.6.4'
    item_title = 'Ensure system wide crypto policy disables macs less than 128 bits'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/crypto-policies/state/CURRENT.pol'
    regex_pattern = re.compile(r'^[ \t]*mac[ \t]*=[ \t]*([^#\n\r]+)?-64\b', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_vulnerable_values = []

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value_items = ret_sp_value.split('=')[1].strip().split()
                for item in ret_sp_value_items:
                    if item.endswith('-64'):
                        is_vulnerable_values.append(item)
                raw_data += (f'[vul] Found: {files_to_check}\n'
                             f'- found: {regex_pattern.pattern} --> `{",".join(is_vulnerable_values)}` '
                             f'near at line: {ret_sp_value_context_num}\n\n'
                             f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                result_code = 0
                raw_data += (f'[ok] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a171(logfile):
    item_no = '1.7.1'
    item_title = 'Ensure message of the day is configured properly'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/motd'
    regex_pattern = re.compile(r'(\\v|\\r|\\m|\\s|rocky|rhel|amzn|ubuntu|centos)', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, False, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                result_code = 1
                ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                raw_data += (f'[vul] Found: {files_to_check}\n'
                             f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                             f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                             f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[ok] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a172(logfile):
    item_no = '1.7.2'
    item_title = 'Ensure local login warning banner is configured properly'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/issue'
    search_regex = re.compile(r'(\\v|\\r|\\m|\\s|rocky|rhel|amzn|ubuntu|centos)', re.IGNORECASE)
    search_regex_type = 'search'
    regex_match = 0

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, False, search_regex_type, search_regex, regex_match)
            if ret_sp_value:
                result_code = 1
                ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                raw_data += (f'[vul] Found: {files_to_check}\n'
                             f'- found: {search_regex.pattern} --> `{ret_sp_value}` '
                             f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                             f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[ok] Not Found: {files_to_check} --> {search_regex.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a173(logfile):
    item_no = '1.7.3'
    item_title = 'Ensure remote login warning banner is configured properly'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/issue.net'
    regex_pattern = re.compile(r'(\\v|\\r|\\m|\\s|rocky|rhel|amzn|ubuntu|centos)', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, False, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                result_code = 1
                ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                raw_data += (f'[vul] Found: {files_to_check}\n'
                             f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                             f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                             f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[ok] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a174(logfile):
    item_no = '1.7.4'
    item_title = 'Ensure access to /etc/motd is configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/motd'
    allowed_values = [644, 600, 440, 400, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 0
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a175(logfile):
    item_no = '1.7.5'
    item_title = 'Ensure access to /etc/issue is configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/issue'
    allowed_values = [644, 600, 440, 400, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 0
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def a176(logfile):
    item_no = '1.7.6'
    item_title = 'Ensure access to /etc/issue.net is configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/issue.net'
    allowed_values = [644, 600, 440, 400, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 0
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b211(logfile):
    item_no = '2.1.1'
    item_title = 'Ensure time synchronization is in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['chronyd.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_vulnerable += 1
                raw_data += (f'[vul] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_not_vulnerable += 1
                raw_data += (f'[ok] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b212(logfile):
    item_no = '2.1.2'
    item_title = 'Ensure chrony is configured'
    result_code = 1
    raw_data = ''
    files_to_check_dict = {
        '/etc/chrony.conf': [
            r'^[ \t]*server[ \t]+[^#\n\r]+\b',
            r'^[ \t]*pool[ \t]+[^#\n\r]+\b'
        ]
    }
    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_not_vulnerable = 0

    for key, values in files_to_check_dict.items():
        for value in values:
            if os.path.exists(key):
                is_file_found += 1
                try:
                    regex_pattern = re.compile(value, re.IGNORECASE)
                    ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                        = grep_search_pattern(key, True, False, regex_type, regex_pattern, regex_match)
                    if ret_sp_value and ret_sp_value_contexts:
                        search_pattern = re.compile(r'^\d+:[ \t]+(server|pool)[ \t]+([^\s]+)([ \t]+[^\s]+)?', re.IGNORECASE | re.MULTILINE)
                        extracted_ret_sp_value_contexts = []
                        for match in search_pattern.finditer(ret_sp_value_contexts):
                            is_not_vulnerable += 1
                            extracted_ret_sp_value_contexts.append(match.group(2))

                        raw_data += (f'[manual] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{",".join(extracted_ret_sp_value_contexts)}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[ok] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                     f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}')
                    raw_data = f'{raw_data}\n\n'
                except Exception as error:
                    result_code = 3
                    raw_data = f'{str(error)}'
            else:
                result_code = 2
                raw_data += f'[ok] No such file or directory: `{key}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b213(logfile):
    item_no = '2.1.3'
    item_title = 'Ensure chrony is not run as the root user'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/sysconfig/chronyd'
    regex_pattern = re.compile(r'^[ \t]*OPTIONS=(\"?[ \t]*([^#\n\r\"]+)\"?|[ \t]*([^#\n\r\"]+))', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value = ret_sp_value.split('=')[1].strip().replace('"', '')
                if ret_sp_value == '-u chrony':
                    result_code = 0
                    raw_data += (f'[ok] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                result_code = 0
                raw_data += (f'[ok] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b221(logfile):
    item_no = '2.2.1'
    item_title = 'Ensure autofs services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['autofs.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b222(logfile):
    item_no = '2.2.2'
    item_title = 'Ensure avahi daemon services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['avahi-daemon.socket', 'avahi-daemon.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b223(logfile):
    item_no = '2.2.3'
    item_title = 'Ensure dhcp server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['dhcpd.service', 'dhcpd6.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b224(logfile):
    item_no = '2.2.4'
    item_title = 'Ensure dns server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['named.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b225(logfile):
    item_no = '2.2.5'
    item_title = 'Ensure dnsmasq services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['dnsmasq.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b226(logfile):
    item_no = '2.2.6'
    item_title = 'Ensure samba file server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['smb.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b227(logfile):
    item_no = '2.2.7'
    item_title = 'Ensure ftp server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['vsftpd.service', 'proftpd.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b228(logfile):
    item_no = '2.2.8'
    item_title = 'Ensure message access server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['dovecot.socket', 'dovecot.service', 'cyrus-imapd.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b229(logfile):
    item_no = '2.2.9'
    item_title = 'Ensure network file system services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['nfs-server.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2210(logfile):
    item_no = '2.2.10'
    item_title = 'Ensure nis server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['ypserv.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2211(logfile):
    item_no = '2.2.11'
    item_title = 'Ensure print server services are not in use '
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['cups.socket', 'cups.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2212(logfile):
    item_no = '2.2.12'
    item_title = 'Ensure rpcbind services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['rpcbind.socket', 'rpcbind.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2213(logfile):
    item_no = '2.2.13'
    item_title = 'Ensure rsync services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['rsyncd.socket', 'rsyncd.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2214(logfile):
    item_no = '2.2.14'
    item_title = 'Ensure snmp services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['snmpd.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2215(logfile):
    item_no = '2.2.15'
    item_title = 'Ensure telnet server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['telnet.socket']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2216(logfile):
    item_no = '2.2.16'
    item_title = 'Ensure tftp server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['tftp.socket', 'tftp.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2217(logfile):
    item_no = '2.2.17'
    item_title = 'Ensure web proxy server services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['squid.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2218(logfile):
    item_no = '2.2.18'
    item_title = 'Ensure web server services are not in use '
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['httpd.socket', 'httpd.service', 'nginx.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2219(logfile):
    item_no = '2.2.19'
    item_title = 'Ensure xinetd services are not in use'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['xinetd.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_not_vulnerable += 1
                raw_data += (f'[ok] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_vulnerable += 1
                raw_data += (f'[vul] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2220(logfile):
    item_no = '2.2.20'
    item_title = 'X window server services are not in use'
    result_code = 1
    pkg_name = 'xorg-x11-server-common'
    cmd = ['rpm', '-qa', pkg_name]

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        if ret_cmd_result:
            raw_data = (f'[vul] Found: {pkg_name}\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result.strip()}')
        else:
            result_code = 0
            raw_data = f'[ok] Not Found: {pkg_name}\n'
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2221(logfile):
    item_no = '2.2.21'
    item_title = 'Ensure mail transfer agents are configured for local-only mode'
    result_code = 2
    raw_data = ''
    cmd = ['ss', '-plntu']
    regex_pattern = re.compile(r'^[ \t]*(tcp|udp)[ \t]*LISTEN[^#\n\r]*\b(:25|:465|:587)\b[^#\n\r]*', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    not_allowed_values = ['127.0.0.1:25', '[::1]:25',
                          '127.0.0.1:465', '[::1]:465',
                          '127.0.0.1:587', '[::1]:587',]
    is_vulnerable_value = []

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
            = grep_search_pattern(ret_cmd_result, False, False, regex_type, regex_pattern, regex_match)
        if ret_sp_value and ret_sp_value_contexts:
            ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
            for value in ret_sp_value_contexts.splitlines():
                value = value.split()[5]
                if value in not_allowed_values:
                    is_vulnerable_value.append(value)

            if len(is_vulnerable_value) >= 1:
                result_code = 1
                raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                             f'- found: `{",".join(is_vulnerable_value)}` '
                             f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                             f'# {" ".join(cmd)}\n...\n{ret_sp_value_contexts}')
            else:
                result_code = 0
                raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                             f'- not found: `{",".join(not_allowed_values)}` '
                             f'near at line:{ret_sp_value_context_num}\n\n'
                             f'# {" ".join(cmd)}\n...\n{ret_sp_value_contexts}')
        else:
            raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                         f'# {" ".join(cmd)}\n{ret_cmd_result}')
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def b2222(logfile):
    item_no = '2.2.22'
    item_title = 'Ensure only approved services are listening on a network interface'
    result_code = 2
    cmd = ['ss', '-plntu']

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        if ret_cmd_result:
            raw_data = (f'[manual] Found: Check Manually\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result.strip()}')
        else:
            result_code = 3
            raw_data = ('[error] Check Manually\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result.strip()}')
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4111(logfile):
    item_no = '4.1.1.1'
    item_title = 'Ensure cron daemon is enabled and active'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['crond.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_vulnerable += 1
                raw_data += (f'[vul] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_not_vulnerable += 1
                raw_data += (f'[ok] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4112(logfile):
    item_no = '4.1.1.2'
    item_title = 'Ensure permissions on /etc/crontab are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/crontab'
    allowed_values = [600, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4113(logfile):
    item_no = '4.1.1.3'
    item_title = 'Ensure permissions on /etc/cron.hourly are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/cron.hourly/'
    allowed_values = [700, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4114(logfile):
    item_no = '4.1.1.4'
    item_title = 'Ensure permissions on /etc/cron.daily are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/cron.daily/'
    allowed_values = [700, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4115(logfile):
    item_no = '4.1.1.5'
    item_title = 'Ensure permissions on /etc/cron.weekly are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/cron.weekly/'
    allowed_values = [700, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4116(logfile):
    item_no = '4.1.1.6'
    item_title = 'Ensure permissions on /etc/cron.monthly are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/cron.monthly/'
    allowed_values = [700, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4117(logfile):
    item_no = '4.1.1.7'
    item_title = 'Ensure permissions on /etc/cron.d are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/cron.d'
    allowed_values = [700, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4118(logfile):
    item_no = '4.1.1.8'
    item_title = 'Ensure crontab is restricted to authorized users'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/cron.allow', '/etc/cron.deny']
    allowed_values = [640, 600, 'root:root']
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_perms_value = filepath_get_perms_value(file)
                ret_owner_group_value = filepath_get_owner_group(file)
                if ret_perms_value is not None and ret_owner_group_value is not None:
                    if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                     f'- permissions: {ret_perms_value}\n'
                                     f'- owner:group: {ret_owner_group_value}')
                    else:
                        raw_data += (f'[vul] {filepath_ls_al(file)}\n'
                                     f'- permissions: {ret_perms_value}\n'
                                     f'- owner:group: {ret_owner_group_value}')
                    raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0
    if is_file_found == 0:
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4121(logfile):
    item_no = '4.1.2.1'
    item_title = 'Ensure at is restricted to authorized users'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/at.allow', '/etc/at.deny']
    allowed_values = [640, 600, 'root:root']
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_perms_value = filepath_get_perms_value(file)
                ret_owner_group_value = filepath_get_owner_group(file)
                if ret_perms_value is not None and ret_owner_group_value is not None:
                    if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                     f'- permissions: {ret_perms_value}\n'
                                     f'- owner:group: {ret_owner_group_value}')
                    else:
                        raw_data += (f'[vul] {filepath_ls_al(file)}\n'
                                     f'- permissions: {ret_perms_value}\n'
                                     f'- owner:group: {ret_owner_group_value}')
                    raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0
    if is_file_found == 0:
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d421(logfile):
    item_no = '4.2.1'
    item_title = 'Ensure permissions on /etc/ssh/sshd_config are configured'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/ssh/sshd_config']
    dirs_to_check = '/etc/ssh/ssh_config.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    allowed_values = [600, 400, 'root:root']
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_perms_value = filepath_get_perms_value(file)
                ret_owner_group_value = filepath_get_owner_group(file)
                if ret_perms_value is not None and ret_owner_group_value is not None:
                    if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                     f'- permissions: {ret_perms_value}\n'
                                     f'- owner:group: {ret_owner_group_value}')
                    else:
                        raw_data += (f'[vul] {filepath_ls_al(file)}\n'
                                     f'- permissions: {ret_perms_value}\n'
                                     f'- owner:group: {ret_owner_group_value}')
                    raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[manual] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d422(logfile):
    item_no = '4.2.2'
    item_title = 'Ensure permissions on SSH private host key files are configured'
    result_code = 1
    raw_data = ''
    files_not_to_check = ['/etc/ssh/moduli', '/etc/ssh/ssh_config',
                          '/etc/ssh/sshd_config', '/etc/ssh/ssh_config.d/05-redhat.conf']
    files_to_check = []
    dirs_to_check = '/etc/ssh/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'OpenSSH\s+private\s+key', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            if file not in files_not_to_check:
                try:
                    ret_sp_value, _, _, ret_raw_file_contents \
                        = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                    if ret_sp_value:
                        ret_perms_value = filepath_get_perms_value(file)
                        ret_owner_group_value = filepath_get_owner_group(file)
                        if ret_owner_group_value == 'root:root' and ret_perms_value in (600, 400):
                            is_not_vulnerable += 1
                            raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                         f'- permissions: {ret_perms_value}\n'
                                         f'- owner:group: {ret_owner_group_value}')
                        elif ret_owner_group_value == 'root:ssh_keys' and ret_perms_value in (640, 440):
                            is_not_vulnerable += 1
                            raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                         f'- permissions: {ret_perms_value}\n'
                                         f'- owner:group: {ret_owner_group_value}')
                        else:
                            raw_data += (f'[vul] {filepath_ls_al(file)}\n'
                                         f'- permissions: {ret_perms_value}\n'
                                         f'- owner:group: {ret_owner_group_value}')
                    else:
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                     f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                    raw_data = f'{raw_data}\n\n'
                except Exception as error:
                    result_code = 3
                    raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{file}`\n'

    if is_not_vulnerable == (len(files_to_check) - len(files_not_to_check)):
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d423(logfile):
    item_no = '4.2.3'
    item_title = 'Ensure permissions on SSH public host key files are configured'
    result_code = 1
    raw_data = ''
    files_not_to_check = ['/etc/ssh/moduli', '/etc/ssh/ssh_config',
                          '/etc/ssh/sshd_config', '/etc/ssh/ssh_config_d/05-redhat.conf']
    files_to_check = []
    dirs_to_check = '/etc/ssh/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'OpenSSH\s+public\s+key', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0
    is_file_found = 0
    is_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            if file not in files_not_to_check:
                try:
                    ret_sp_value, _, _, ret_raw_file_contents \
                        = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                    if ret_sp_value:
                        ret_perms_value = filepath_get_perms_value(file)
                        ret_owner_group_value = filepath_get_owner_group(file)
                        if ret_owner_group_value == 'root:root' and ret_perms_value in (600, 400):
                            raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                         f'- permissions: {ret_perms_value}\n'
                                         f'- owner:group: {ret_owner_group_value}')
                        elif ret_owner_group_value == 'root:ssh_keys' and ret_perms_value in (640, 440):
                            raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                         f'- permissions: {ret_perms_value}\n'
                                         f'- owner:group: {ret_owner_group_value}')
                        else:
                            is_vulnerable += 1
                            raw_data += (f'[vul] {filepath_ls_al(file)}\n'
                                         f'- permissions: {ret_perms_value}\n'
                                         f'- owner:group: {ret_owner_group_value}')
                    else:
                        raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                     f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                    raw_data = f'{raw_data}\n\n'
                except Exception as error:
                    result_code = 3
                    raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{file}`\n'

    if is_vulnerable == 0:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d424(logfile):
    item_no = '4.2.4'
    item_title = 'Ensure sshd access is configured'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^\s*(Allow|Deny)(Users|Groups)\s+\S+(\s+.*)?$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                result_code = 0
                raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                             f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                             f'near at line:{ret_sp_value_context_num}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d425(logfile):
    item_no = '4.2.5'
    item_title = 'Ensure sshd Banner is configured'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*Banner[ \t]*.*$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                result_code = 0
                raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                             f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                             f'near at line:{ret_sp_value_context_num}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d426(logfile):
    item_no = '4.2.6'
    item_title = 'Ensure sshd Ciphers are configured'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*Ciphers[ \t]*.*$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    not_allowed_values = ['3des-cbc', 'aes128-cbc', 'aes192-cbc',
                          'aes256-cbc', 'rijndael-cbc@lysator.liu.se']
    is_vulnerable_value = []

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value = ret_sp_value.split(' ')[1].split(',')
                for value in ret_sp_value:
                    if value in not_allowed_values:
                        is_vulnerable_value.append(value)

                if len(is_vulnerable_value) >= 1:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: `{",".join(is_vulnerable_value)}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- not found: `{",".join(not_allowed_values)}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d427(logfile):
    item_no = '4.2.7'
    item_title = 'Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured'
    result_code = 2
    raw_data = ''
    regex_type = 'match'
    regex_match = 0
    regex_patterns = ['ClientAliveCountMax', 'ClientAliveInterval']
    is_not_vulnerable = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            for pattern in regex_patterns:
                regex_pattern = re.compile(rf'^[ \t]*{pattern}[ \t]*(\d+)$', re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                    grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    ret_sp_name = ret_sp_value.split(' ')[0]
                    ret_sp_value = int(ret_sp_value.split(' ')[1])

                    if ret_sp_name.lower() == 'clientalivecountmax' and ret_sp_value == 3:
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                     f'- found:  {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line:{ret_sp_value_context_num}\n\n'
                                     f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                    elif ret_sp_name.lower() == 'clientaliveinterval' and ret_sp_value == 15:
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                     f'- found:  {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line:{ret_sp_value_context_num}\n\n'
                                     f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                    else:
                        result_code = 1
                        raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                     f'- found:  {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line:{ret_sp_value_context_num}\n\n'
                                     f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
                raw_data = f'{raw_data}\n\n'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'

        if is_not_vulnerable == len(regex_patterns):
            result_code = 0

    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d428(logfile):
    item_no = '4.2.8'
    item_title = 'Ensure sshd DisableForwarding is enabled'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*DisableForwarding[ \t]*(yes|no)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = ret_sp_value.split(' ')[1]

                if ret_sp_name.lower() == 'disableforwarding' and ret_sp_value == 'yes':
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d429(logfile):
    item_no = '4.2.9'
    item_title = 'Ensure sshd HostbasedAuthentication is disabled'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*HostbasedAuthentication[ \t]*(yes|no)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = ret_sp_value.split(' ')[1]

                if ret_sp_name.lower() == 'hostbasedauthentication' and ret_sp_value == 'no':
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4210(logfile):
    item_no = '4.2.10'
    item_title = 'Ensure sshd IgnoreRhosts is enabled '
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*IgnoreRhosts[ \t]*(yes|no)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = ret_sp_value.split(' ')[1]

                if ret_sp_name.lower() == 'ignorerhosts' and ret_sp_value == 'yes':
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4211(logfile):
    item_no = '4.2.11'
    item_title = 'Ensure sshd KexAlgorithms is configured'
    result_code = 2
    raw_data = ''

    regex_pattern = re.compile(r'^[ \t]*KexAlgorithms[ \t]*.*$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    not_allowed_values = ['diffie-hellman-group1-sha1',
                          'diffie-hellman-group14-sha1',
                          'diffie-hellman-group-exchange-sha1']
    is_vulnerable_value = []

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value = ret_sp_value.split(' ')[1].split(',')
                for value in ret_sp_value:
                    if value in not_allowed_values:
                        is_vulnerable_value.append(value)

                if len(is_vulnerable_value) >= 1:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: `{",".join(is_vulnerable_value)}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- not found: `{",".join(not_allowed_values)}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4212(logfile):
    item_no = '4.2.12'
    item_title = 'Ensure sshd LoginGraceTime is configured'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*LoginGraceTime[ \t]*(\d+)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = int(ret_sp_value.split(' ')[1])

                if ret_sp_name.lower() == 'logingracetime' and 1 <= ret_sp_value <= 60:
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4213(logfile):
    item_no = '4.2.13'
    item_title = 'Ensure sshd LogLevel is configured'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*LogLevel[ \t]*(VERBOSE|INFO)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    allowed_values = ['info', 'verbose']

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = ret_sp_value.split(' ')[1]

                if ret_sp_name.lower() == 'loglevel' and ret_sp_value.lower() in allowed_values:
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4214(logfile):
    item_no = '4.2.14'
    item_title = 'Ensure sshd MACs are configured'
    result_code = 2
    raw_data = ''

    regex_pattern = re.compile(r'^[ \t]*MACs[ \t]*.*$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    not_allowed_values = ['hmac-md5', 'hmac-md5-96', 'hmac-ripemd160',
                          'hmac-sha1-96', 'umac-64@openssh.com', 'hmac-md5-etm@openssh.com',
                          'hmac-md5-96-etm@openssh.com', 'hmac-ripemd160-etm@openssh.com',
                          'hmac-sha1-96-etm@openssh.com', 'umac-64-etm@openssh.com']
    is_vulnerable_value = []

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value = ret_sp_value.split(' ')[1].split(',')
                for value in ret_sp_value:
                    if value in not_allowed_values:
                        is_vulnerable_value.append(value)

                if len(is_vulnerable_value) >= 1:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: `{",".join(is_vulnerable_value)}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- not found: `{",".join(not_allowed_values)}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'

    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4215(logfile):
    item_no = '4.2.15'
    item_title = 'Ensure sshd MaxAuthTries is configured '
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*MaxAuthTries[ \t]*(\d+)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = int(ret_sp_value.split(' ')[1])

                if ret_sp_name.lower() == 'maxauthtries' and ret_sp_value <= 4:
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4216(logfile):
    item_no = '4.2.16'
    item_title = 'Ensure sshd MaxSessions is configured'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*MaxSessions[ \t]*(\d+)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = int(ret_sp_value.split(' ')[1])

                if ret_sp_name.lower() == 'maxsessions' and ret_sp_value <= 10:
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4217(logfile):
    item_no = '4.2.17'
    item_title = 'Ensure sshd MaxStartups is configured'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*MaxStartups[ \t]*(\d+:\d+:\d+)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    allowed_values = ['10:30:60', '2:90:4']
    is_not_vulnerable_value = []

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value = ret_sp_value.split(' ')[1]
                for value in allowed_values:
                    if value in ret_sp_value:
                        is_not_vulnerable_value.append(value)

                if len(is_not_vulnerable_value) >= 1:
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: `{",".join(is_not_vulnerable_value)}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- not found: `{",".join(allowed_values)}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4218(logfile):
    item_no = '4.2.18'
    item_title = 'Ensure sshd PermitEmptyPasswords is disabled'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*PermitEmptyPasswords[ \t]*(yes|no)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = ret_sp_value.split(' ')[1]

                if ret_sp_name.lower() == 'permitemptypasswords' and ret_sp_value == 'no':
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4219(logfile):
    item_no = '4.2.19'
    item_title = 'Ensure sshd PermitRootLogin is disabled'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*PermitRootLogin[ \t]*(yes|prohibit-password|forced-commands- only|no)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = ret_sp_value.split(' ')[1]

                if ret_sp_name.lower() == 'permitrootlogin' and ret_sp_value == 'no':
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4220(logfile):
    item_no = '4.2.20'
    item_title = 'Ensure sshd PermitUserEnvironment is disabled'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*PermitUserEnvironment[ \t]*(yes|no)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = ret_sp_value.split(' ')[1]

                if ret_sp_name.lower() == 'permituserenvironment' and ret_sp_value == 'no':
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4221(logfile):
    item_no = '4.2.21'
    item_title = 'Ensure sshd UsePAM is enabled'
    result_code = 2
    raw_data = ''
    regex_pattern = re.compile(r'^[ \t]*UsePAM[ \t]*(yes|no)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    ret_status, ret_run_cmd_value, ret_status_value = get_current_sshd_config()
    if ret_status == '[ok]':
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ = \
                grep_search_pattern(ret_status_value, False, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_name = ret_sp_value.split(' ')[0]
                ret_sp_value = ret_sp_value.split(' ')[1]

                if ret_sp_name.lower() == 'usepam' and ret_sp_value == 'yes':
                    result_code = 0
                    raw_data += (f'[ok] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
                else:
                    result_code = 1
                    raw_data += (f'[vul] Found: {regex_pattern.pattern}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line:{ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[manual] Not Found: {regex_pattern.pattern}\n\n'
                             f'# {" ".join(ret_run_cmd_value)}\n...\n{ret_status_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data = f'[error] Fail to get current SSHD Config: Check Manually\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4222(logfile):
    item_no = '4.2.22'
    item_title = 'Ensure sshd crypto_policy is not set'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/sysconfig/sshd'
    regex_pattern = re.compile(r'^[ \t]*(CRYPTO_POLICY[ \t]*=.*)$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value = ret_sp_value.split('=')[1]
                if len(ret_sp_value) == 0:
                    result_code = 0
                    raw_data += (f'[ok] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `null` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[vul] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}\n\n')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d431(logfile):
    item_no = '4.3.1'
    item_title = 'Ensure sudo is installed'
    result_code = 1
    pkg_name = 'sudo'
    cmd = ['rpm', '-qa', pkg_name]

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        if ret_cmd_result:
            result_code = 0
            raw_data = (f'[ok] Found: {pkg_name}\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result.strip()}')
        else:
            raw_data = f'[vul] Not Found: {pkg_name}\n'
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d432(logfile):
    item_no = '4.3.2'
    item_title = 'Ensure sudo commands use pty'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/sudoers']
    dirs_to_check = '/etc/sudoers.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[ \t]*Defaults[ \t]+([^#\n\r]+,)?use_pty(,[ \t]*[ \t]+[ \t]*)*[ \t]*(#.*)?$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if is_not_vulnerable >= 1:
            break
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d433(logfile):
    item_no = '4.3.3'
    item_title = 'Ensure sudo log file exists'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/sudoers']
    dirs_to_check = '/etc/sudoers.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[ \t]*Defaults[ \t]+([^#]+,\s*)?logfile[ \t]*=[ \t]*(["\']?)\S+(["\']?)(,\s*\S+\s*)*\s*(#.*)?$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if is_not_vulnerable >= 1:
            break
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d434(logfile):
    item_no = '4.3.4'
    item_title = 'Ensure users must provide password for escalation'
    result_code = 2
    raw_data = ''
    files_to_check = ['/etc/sudoers']
    dirs_to_check = '/etc/sudoers.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[^#].*NOPASSWD', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_vulnerable = 0

    for file in files_to_check:
        if is_vulnerable >= 1:
            break
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_vulnerable += 1
                    ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                    raw_data += (f'[manual] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d435(logfile):
    item_no = '4.3.5'
    item_title = 'Ensure re-authentication for privilege escalation is not disabled globally'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/sudoers']
    dirs_to_check = '/etc/sudoers.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[^#].*!authenticate\s*(#.*)?$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if is_not_vulnerable >= 1:
            break
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    raw_data += (f'[vul] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d436(logfile):
    item_no = '4.3.6'
    item_title = 'Ensure sudo authentication timeout is configured correctly'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/sudoers']
    dirs_to_check = '/etc/sudoers.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[^#].*timestamp_timeout[ \t]*=[ \t]*(\d+)', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\btimestamp_timeout[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    if 5 <= int(matched_obj_value) <= 15:
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] Found: {file}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {file}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {file}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d437(logfile):
    item_no = '4.3.7'
    item_title = 'Ensure access to the su command is restricted'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/pam.d/su'
    regex_pattern = re.compile(r'^[ \t]*auth[ \t]+(?:required|requisite)[ \t]+pam_wheel\.so[ \t]+([^#,\s]+,\s*)?use_uid[ \t]+group[ \t]*=[ \t]*(["\']?)\S+(["\']?)(,\s*\S+\s*)*\s*(#.*)?$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, False, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                result_code = 2
                ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                ret_sp_value = re.sub(r'(?<=\S)\s+(?=\S)', ' ', ret_sp_value)
                raw_data += (f'[manual] Found: {files_to_check}\n'
                             f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                             f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                             f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[ok] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4421(logfile):
    item_no = '4.4.2.1'
    item_title = 'Ensure active authselect profile includes pam modules'
    result_code = 2
    raw_data = ''
    files_to_find = ['password-auth', 'system-auth']
    files_to_check = []
    dirs_to_check = '/etc/authselect/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file in files_to_find:
                    files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'\b(pam_pwquality\.so|pam_pwhistory\.so|pam_faillock\.so|pam_unix\.so)\b', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0
    is_not_found = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                    ret_sp_value = re.sub(r'(?<=\S)\s+(?=\S)', ' ', ret_sp_value)
                    raw_data += (f'[manual] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    is_not_found += 1
                    raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_found == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4422(logfile):
    item_no = '4.4.2.2'
    item_title = 'pam_faillock module is enabled'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'\bpam_faillock\.so\b', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                    ret_sp_value = re.sub(r'(?<=\S)\s+(?=\S)', ' ', ret_sp_value)
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4423(logfile):
    item_no = '4.4.2.3'
    item_title = 'pam_pwquality module is enabled'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'\bpam_pwquality\.so\b', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4424(logfile):
    item_no = '4.4.2.4'
    item_title = 'Ensure pam_pwhistory module is enabled'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'\bpam_pwhistory\.so\b', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4425(logfile):
    item_no = '4.4.2.5'
    item_title = 'Ensure pam_unix module is enabled'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'\bpam_unix\.so\b', re.IGNORECASE)
    regex_type = 'search'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                    ret_sp_value = re.sub(r'(?<=\S)\s+(?=\S)', ' ', ret_sp_value)
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44311(logfile):
    item_no = '4.4.3.1.1'
    item_title = 'Ensure password failed attempts lockout is configured'
    result_code = 1
    raw_data = ''

    files_to_check_dict = {
        '/etc/pam.d/system-auth':
            r'^[ \t]*auth[ \t]+(requisite|required|sufficient)[ \t]+pam_faillock\.so[ \t]+.*?[ \t]*(deny[ \t]*=[ \t]*(\d+)\b).*',
        '/etc/pam.d/password-auth':
            r'^[ \t]*auth[ \t]+(requisite|required|sufficient)[ \t]+pam_faillock\.so[ \t]+.*?[ \t]*(deny[ \t]*=[ \t]*(\d+)\b).*',
        '/etc/security/faillock.conf':
            r'^[ \t]*deny[ \t]*=[ \t]*(\d+)'
    }

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_vulnerable = 0

    for key, value in files_to_check_dict.items():
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bdeny[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    if int(matched_obj_value) <= 5:
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        is_vulnerable += 1
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    is_vulnerable += 1
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

    if is_vulnerable == 0:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44312(logfile):
    item_no = '4.4.3.1.2'
    item_title = 'Ensure password unlock time is configured'
    result_code = 1
    raw_data = ''

    files_to_check_dict = {
        '/etc/pam.d/system-auth':
            r'^[ \t]*auth[ \t]+(requisite|required|sufficient)[ \t]+pam_faillock\.so[ \t]+.*?[ \t]*(unlock_time[ \t]*=[ \t]*(\d+)\b).*',
        '/etc/pam.d/password-auth':
            r'^[ \t]*auth[ \t]+(requisite|required|sufficient)[ \t]+pam_faillock\.so[ \t]+.*?[ \t]*(unlock_time[ \t]*=[ \t]*(\d+)\b).*',
        '/etc/security/faillock.conf':
            r'^[ \t]*unlock_time[ \t]*=[ \t]*(\d+)\b'
    }

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_vulnerable = 0

    for key, value in files_to_check_dict.items():
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bunlock_time[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    if 1 <= int(matched_obj_value) <= 900:
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        is_vulnerable += 1
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    is_vulnerable += 1
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

    if is_vulnerable == 0:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44313(logfile):
    item_no = '4.4.3.1.3'
    item_title = 'Ensure password failed attempts lockout includes root account'
    result_code = 2
    raw_data = ''

    files_to_check_dict = {
        '/etc/pam.d/system-auth': [
            r'^[ \t]*auth[ \t]+([^#\n\r]+[ \t]+)pam_faillock\.so[ \t]+([^#\n\r]+[ \t]+)?root_unlock_time[ \t]*=[ \t]*(\d+)\b'
        ],
        '/etc/pam.d/password-auth': [
            r'^[ \t]*auth[ \t]+([^#\n\r]+[ \t]+)pam_faillock\.so[ \t]+([^#\n\r]+[ \t]+)?root_unlock_time[ \t]*=[ \t]*(\d+)\b'
        ],
        '/etc/security/faillock.conf': [
            r'^[ \t]*(even_deny_root)\b',
            r'^[ \t]*(root_unlock_time[ \t]*=[ \t]*\d+)\b'
        ]
    }

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0

    for key, values in files_to_check_dict.items():
        for value in values:
            if os.path.exists(key):
                is_file_found += 1
                try:
                    regex_pattern = re.compile(value, re.IGNORECASE)
                    ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                        = grep_search_pattern(key, True, False, regex_type, regex_pattern, regex_match)
                    if ret_sp_value:
                        if 'root_unlock_time' in ret_sp_value:
                            matched_obj = re.search(r'\broot_unlock_time[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                        else:
                            matched_obj = ret_sp_value
                        raw_data += (f'[manual] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[manual] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                     f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                    raw_data = f'{raw_data}\n\n'
                except Exception as error:
                    result_code = 3
                    raw_data = f'{str(error)}'
            else:
                raw_data += f'[manual] No such file or directory: `{key}`\n'

        if is_file_found == 0:
            result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44321(logfile):
    item_no = '4.4.3.2.1'
    item_title = 'Ensure password number of changed characters is configured'
    result_code = 1
    raw_data = ''

    files_to_check = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth', '/etc/security/pwquality.conf']
    dirs_to_check = '/etc/security/pwquality.conf.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    files_to_check_dict = {}
    regex_on_auth = r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?\bdifok[ \t]*=[ \t]*(\d+)\b.*'
    regex_on_conf = r'^[ \t]*difok[ \t]*=[ \t]*(\d+)\b'

    for file in files_to_check:
        if file.endswith('.conf'):
            files_to_check_dict[file] = regex_on_conf
        else:
            files_to_check_dict[file] = regex_on_auth

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_set_values = []
    is_set_on_conf = 0
    is_set_on_auth = 0

    for key, value in files_to_check_dict.items():
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bdifok[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    is_set_values.append(key)
                    if int(matched_obj_value) >= 2:
                        if key.endswith('.conf'):
                            is_set_on_conf += 1
                        else:
                            is_set_on_auth += 1
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

    if is_set_on_conf >= 1 and is_set_on_auth == 0:
        result_code = 0
    elif is_set_on_auth == 0 and is_set_on_auth == 2:
        result_code = 0

    if is_set_values:
        raw_data = f'{raw_data}\n- `difork` is set on: {is_set_values}\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44322(logfile):
    item_no = '4.4.3.2.2'
    item_title = 'Ensure password length is configured'
    result_code = 1
    raw_data = ''

    files_to_check = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth', '/etc/security/pwquality.conf']
    dirs_to_check = '/etc/security/pwquality.conf.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    files_to_check_dict = {}
    regex_on_auth = r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?\bminlen[ \t]*=[ \t]*(\d+)\b.*'
    regex_on_conf = r'^[ \t]*minlen[ \t]*=[ \t]*(\d+)\b'

    for file in files_to_check:
        if file.endswith('.conf'):
            files_to_check_dict[file] = regex_on_conf
        else:
            files_to_check_dict[file] = regex_on_auth

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_set_values = []
    is_set_on_conf = 0
    is_set_on_auth = 0

    for key, value in files_to_check_dict.items():
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bminlen[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    is_set_values.append(key)
                    if int(matched_obj_value) >= 14:
                        if key.endswith('.conf'):
                            is_set_on_conf += 1
                        else:
                            is_set_on_auth += 1
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

    if is_set_on_conf >= 1 and is_set_on_auth == 0:
        result_code = 0
    elif is_set_on_auth == 0 and is_set_on_auth == 2:
        result_code = 0

    if is_set_values:
        raw_data = f'{raw_data}\n- `minlen` is set on: {is_set_values}\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44323(logfile):
    item_no = '4.4.3.2.3'
    item_title = 'Ensure password complexity is configured'
    result_code = 1
    raw_data = ''

    files_to_check = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth', '/etc/security/pwquality.conf']
    dirs_to_check = '/etc/security/pwquality.conf.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    files_to_check_dict = {}

    regex_on_auth = [
        r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?minclass[ \t]*=[ \t]*(\d+)',
        r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?dcredit[ \t]*=[ \t]*([-]?\d+)',
        r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?ucredit[ \t]*=[ \t]*([-]?\d+)',
        r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?lcredit[ \t]*=[ \t]*([-]?\d+)',
        r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?ocredit[ \t]*=[ \t]*([-]?\d+)'
    ]

    regex_on_conf_list = [
        r'^[ \t]*minclass[ \t]*=[ \t]*([-]?\d+)\b',
        r'^[ \t]*dcredit[ \t]*=[ \t]*([-]?\d+)\b',
        r'^[ \t]*ucredit[ \t]*=[ \t]*([-]?\d+)\b',
        r'^[ \t]*lcredit[ \t]*=[ \t]*([-]?\d+)\b',
        r'^[ \t]*ocredit[ \t]*=[ \t]*([-]?\d+)\b'
    ]

    for file in files_to_check:
        if file.endswith('.conf'):
            files_to_check_dict[file] = regex_on_conf_list
        else:
            files_to_check_dict[file] = regex_on_auth

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_set_values_info = ''
    is_set_on_conf = 0
    is_set_on_auth = 0

    for key, values in files_to_check_dict.items():
        is_set_values = []
        for value in values:
            if os.path.exists(key):
                is_file_found += 1
                try:
                    regex_pattern = re.compile(value, re.IGNORECASE)
                    ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                        = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                    if ret_sp_value:
                        if key.lower().endswith('-auth'):
                            ret_sp_value = ret_sp_value.rsplit(maxsplit=1)
                            ret_sp_value = ret_sp_value[-1] if ret_sp_value else None
                            if ret_sp_value:
                                if ret_sp_value.split('=')[0].strip().lower().endswith('credit'):
                                    if ret_sp_value.split('=')[1].strip() in ['-1', '-2']:
                                        is_set_on_auth += 1
                        elif key.lower().endswith('.conf'):
                            if ret_sp_value.split('=')[1].strip() in ['-1', '-2']:
                                is_set_on_conf += 1

                        is_set_values.append(ret_sp_value)
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                     f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                    raw_data = f'{raw_data}\n\n'
                except Exception as error:
                    result_code = 3
                    raw_data = f'{str(error)}'
            else:
                raw_data += f'[manual] No such file or directory: `{key}`\n'

        if is_set_values:
            is_set_values_info = f'{is_set_values_info}\n{key} --> {is_set_values}'

    if is_set_on_conf >= 1 and is_set_on_auth == 0:
        result_code = 0
    elif is_set_on_conf == 0 and is_set_on_auth == 2:
        result_code = 0

    if is_set_values_info:
        raw_data = f'{raw_data}Summary:{is_set_values_info}\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44324(logfile):
    item_no = '4.4.3.2.4'
    item_title = 'Ensure password same consecutive characters is configured'
    result_code = 1
    raw_data = ''

    files_to_check = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth', '/etc/security/pwquality.conf']
    dirs_to_check = '/etc/security/pwquality.conf.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    files_to_check_dict = {}
    regex_on_auth = r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?\bmaxrepeat[ \t]*=[ \t]*(\d+)\b.*'
    regex_on_conf = r'^[ \t]*maxrepeat[ \t]*=[ \t]*(\d+)\b'

    for file in files_to_check:
        if file.endswith('.conf'):
            files_to_check_dict[file] = regex_on_conf
        else:
            files_to_check_dict[file] = regex_on_auth

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_set_values_info = ''
    is_set_on_conf = 0
    is_set_on_auth = 0

    for key, value in files_to_check_dict.items():
        is_set_values = []
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bmaxrepeat[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    is_set_values.append(matched_obj)
                    if 1 <= int(matched_obj_value) <= 3:
                        if key.endswith('.conf'):
                            is_set_on_conf += 1
                        else:
                            is_set_on_auth += 1
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

        if is_set_values:
            is_set_values_info = f'{is_set_values_info}\n{key} --> {is_set_values}'

    if is_set_on_conf >= 1 and is_set_on_auth == 0:
        result_code = 0
    elif is_set_on_auth == 0 and is_set_on_auth == 2:
        result_code = 0

    if is_set_values_info:
        raw_data = f'{raw_data}Summary:{is_set_values_info}\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44325(logfile):
    item_no = '4.4.3.2.5'
    item_title = 'Ensure password maximum sequential characters is configured'
    result_code = 1
    raw_data = ''

    files_to_check = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth', '/etc/security/pwquality.conf']
    dirs_to_check = '/etc/security/pwquality.conf.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    files_to_check_dict = {}
    regex_on_auth = r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?\bmaxsequence[ \t]*=[ \t]*(\d+)\b.*'
    regex_on_conf = r'^[ \t]*maxsequence[ \t]*=[ \t]*(\d+)\b'

    for file in files_to_check:
        if file.endswith('.conf'):
            files_to_check_dict[file] = regex_on_conf
        else:
            files_to_check_dict[file] = regex_on_auth

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_set_values_info = ''
    is_set_on_conf = 0
    is_set_on_auth = 0

    for key, value in files_to_check_dict.items():
        is_set_values = []
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bmaxsequence[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    is_set_values.append(matched_obj)
                    if 1 <= int(matched_obj_value) <= 3:
                        if key.endswith('.conf'):
                            is_set_on_conf += 1
                        else:
                            is_set_on_auth += 1
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

        if is_set_values:
            is_set_values_info = f'{is_set_values_info}\n{key} --> {is_set_values}'

    if is_set_on_conf >= 1 and is_set_on_auth == 0:
        result_code = 0
    elif is_set_on_conf == 0 and is_set_on_auth == 2:
        result_code = 0

    if is_set_values_info:
        raw_data = f'{raw_data}Summary:{is_set_values_info}\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44326(logfile):
    item_no = '4.4.3.2.6'
    item_title = 'Ensure password dictionary check is enabled'
    result_code = 1
    raw_data = ''

    files_to_check = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth', '/etc/security/pwquality.conf']
    dirs_to_check = '/etc/security/pwquality.conf.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    files_to_check_dict = {}
    regex_on_auth = r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwquality\.so[ \t]+([^#\n\r]+[ \t]+)?\bdictcheck[ \t]*=[ \t]*(\d+)\b.*'
    regex_on_conf = r'^[ \t]*dictcheck[ \t]*=[ \t]*(\d+)\b'

    for file in files_to_check:
        if file.endswith('.conf'):
            files_to_check_dict[file] = regex_on_conf
        else:
            files_to_check_dict[file] = regex_on_auth

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_set_values_info = ''
    is_set_on_conf = 0
    is_set_on_auth = 0

    for key, value in files_to_check_dict.items():
        is_set_values = []
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bdictcheck[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    is_set_values.append(matched_obj)
                    if not int(matched_obj_value) == 0:
                        if key.endswith('.conf'):
                            is_set_on_conf += 1
                        else:
                            is_set_on_auth += 1
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

        if is_set_values:
            is_set_values_info = f'{is_set_values_info}\n{key} --> {is_set_values}'

    if is_set_on_conf >= 1 and is_set_on_auth == 0:
        result_code = 0
    elif is_set_on_conf == 0 and is_set_on_auth == 2:
        result_code = 0

    if is_set_values_info:
        raw_data = f'{raw_data}Summary:{is_set_values_info}\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44327(logfile):
    item_no = '4.4.3.2.7'
    item_title = 'Ensure password quality is enforced for the root user'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/security/pwquality.conf']
    dirs_to_check = '/etc/security/pwquality.conf.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[ \t]*(\benforce_for_root\b)', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_file_found = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    result_code = 0
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44331(logfile):
    item_no = '4.4.3.3.1'
    item_title = 'Ensure password history remember is configured'
    result_code = 1
    raw_data = ''

    files_to_check_dict = {
        '/etc/pam.d/system-auth':
            r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwhistory\.so[ \t]+([^#\n\r]+[ \t]+)?\bremember[ \t]*=[ \t]*(\d+)\b.*',
        '/etc/pam.d/password-auth':
            r'^[ \t]*password[ \t]+(requisite|required|sufficient)[ \t]+pam_pwhistory\.so[ \t]+([^#\n\r]+[ \t]+)?\bremember[ \t]*=[ \t]*(\d+)\b.*',
        '/etc/security/pwhistory.conf':
            r'^[ \t]*remember[ \t]*=[ \t]*(\d+)'
    }

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_vulnerable = 0

    for key, value in files_to_check_dict.items():
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bremember[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    matched_obj_value = matched_obj.split('=')[1].strip()
                    if int(matched_obj_value) >= 24:
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        is_vulnerable += 1
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    is_vulnerable += 1
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

    if is_vulnerable == 0:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44332(logfile):
    item_no = '4.4.3.3.2'
    item_title = 'Ensure password history is enforced for the root user'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/security/pwhistory.conf'
    regex_pattern = re.compile(r'^[ \t]*(\benforce_for_root\b)', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                result_code = 0
                raw_data += (f'[ok] Found: {files_to_check}\n'
                             f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                             f'near at line: {ret_sp_value_context_num}\n\n'
                             f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[vul] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[ok] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44333(logfile):
    item_no = '4.4.3.3.3'
    item_title = 'Ensure pam_pwhistory includes use_authtok'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'^[ \t]*password[ \t]+([^#\n\r]+)[ \t]+pam_pwhistory\.so[ \t]+([^#\n\r]+[ \t]+)?use_authtok\b', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    matched_obj = re.search(r'\buse_authtok\b', ret_sp_value).group(0)
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44341(logfile):
    item_no = '4.4.3.4.1'
    item_title = 'Ensure pam_unix does not include nullok'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'^[ \t]*(auth|account|password|session)[ \t]+(requisite|required|sufficient)[ \t]+pam_unix\.so[ \t]+.*?nullok.*', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bnullok\b', ret_sp_value).group(0)
                    raw_data += (f'[vul] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44342(logfile):
    item_no = '4.4.3.4.2'
    item_title = 'Ensure pam_unix does not include remember'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'^[ \t]*password[ \t]+([^#\n\r]+[ \t]+)?pam_unix\.so[ \t]+.*?[ \t]*\bremember[ \t]*=[ \t]*(\d+)\b.*', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    matched_obj = re.search(r'\bremember[ \t]*=[ \t]*\d+\b', ret_sp_value).group(0)
                    raw_data += (f'[vul] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44343(logfile):
    item_no = '4.4.3.4.3'
    item_title = 'Ensure pam_unix includes a strong password hashing algorithm'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'^[ \t]*password[ \t]+([^#\n\r]+)[ \t]+pam_unix\.so[ \t]+([^#\n\r]+[ \t]+)?(sha512|yescrypt)\b', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    matched_obj = re.search(r'(sha512|yescrypt)\b', ret_sp_value).group(0)
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d44344(logfile):
    item_no = '4.4.3.4.4'
    item_title = 'Ensure pam_unix includes use_authtok '
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth']
    regex_pattern = re.compile(r'^[ \t]*password[ \t]+([^#\n\r]+)[ \t]+pam_unix\.so[ \t]+([^#\n\r]+[ \t]+)?use_authtok\b', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    matched_obj = re.search(r'\buse_authtok\b', ret_sp_value).group(0)
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{matched_obj}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable == len(files_to_check):
        result_code = 0

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4511(logfile):
    item_no = '4.5.1.1'
    item_title = 'Ensure strong password hashing algorithm is configured'
    result_code = 1
    raw_data = ''

    files_to_check_dict = {
        '/etc/libuser.conf': r'^[ \t]*crypt_style[ \t]*=[ \t]*(sha512|yescrypt)$',
        '/etc/login.defs': r'^[ \t]*ENCRYPT_METHOD[ \t]*(sha512|yescrypt)$'
    }

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_not_vulnerable = 0

    for key, value in files_to_check_dict.items():
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Found: {key}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}\n\n')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{key}`\n'

    if is_file_found == 2 and is_not_vulnerable == len(files_to_check_dict):
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4512(logfile):
    item_no = '4.5.1.2'
    item_title = 'Ensure password expiration policy is 180 days or less'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/login.defs'
    regex_pattern = re.compile(r'^[ \t]*PASS_MAX_DAYS[ \t]*(\d+)', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 1

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value = int(ret_sp_value)
                if ret_sp_value <= 180:
                    result_code = 0
                    raw_data += (f'[ok] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[vul] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}\n\n')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4513(logfile):
    item_no = '4.5.1.3'
    item_title = 'Ensure password expiration warning days is 7 or more'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/login.defs'
    regex_pattern = re.compile(r'^[ \t]*PASS_WARN_AGE[ \t]*(\d+)', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 1

    if os.path.exists(files_to_check):
        try:
            ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                = grep_search_pattern(files_to_check, True, True, regex_type, regex_pattern, regex_match)
            if ret_sp_value:
                ret_sp_value = int(ret_sp_value)
                if ret_sp_value >= 7:
                    result_code = 0
                    raw_data += (f'[ok] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num }\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Found: {files_to_check}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {files_to_check}\n...\n{ret_sp_value_contexts}')
            else:
                raw_data += (f'[vul] Not Found: {files_to_check} --> {regex_pattern.pattern}\n\n'
                             f'# cat {files_to_check}\n...\n{"".join(ret_raw_file_contents)}\n\n')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4514(logfile):
    item_no = '4.5.1.4'
    item_title = 'Ensure inactive password lock is 30 days or less'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/shadow'
    valid_max_inactive = 30
    inactive_policy = ''

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for line in file_content:
                fields = line.strip().split(':')

                if len(fields) < 2 or not fields[1] or fields[1].startswith(('*', '!', '!!')):
                    continue

                if len(fields) < 8 or not fields[7] or fields[7] == '':
                    inactive_days = -1
                else:
                    try:
                        inactive_days = int(fields[7])
                    except ValueError:
                        inactive_days = -1

                if inactive_days == -1 or inactive_days > valid_max_inactive:
                    result_code = 1  # 취약
                    if inactive_days == -1:
                        inactive_policy = 'Not Configure'
                    raw_data += f'[vul] {fields[0]}:{fields[1][:8]}...:{":".join(fields[2:])} --> `inactive: {inactive_policy}`\n'
                else:
                    raw_data += f'[ok] {fields[0]}:{fields[1][:8]}...:{":".join(fields[2:])}\n'

            raw_data = f'# cat {files_to_check}\n...\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4515(logfile):
    item_no = '4.5.1.5'
    item_title = 'Ensure all users last password change date is in the past'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/shadow'
    init_pw_age = 0
    valid_pw_age = 180

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                fields = line.strip().split(':')

                if len(fields) < 2 or not fields[1] or fields[1].startswith(('*', '!')):
                    continue

                if not len(fields[2]) == 0:
                    init_pw_age = int(fields[2])

                datetime_string_last_pw_changed_date = datetime(1970, 1, 1) + timedelta(days=init_pw_age)
                ret_last_pw_change_value = (datetime.now() - datetime_string_last_pw_changed_date).days
                ret_pw_info = (f'--> `password age: {ret_last_pw_change_value} (days) | '
                               f'last changed: {datetime_string_last_pw_changed_date.strftime("%Y-%m-%d")}`\n')
                if ret_last_pw_change_value > valid_pw_age:
                    result_code = 1
                    raw_data += f'[vul] {fields[0]}:{fields[1][:8]}...:{":".join(fields[2:])} {ret_pw_info}'
                else:
                    raw_data += f'[ok] {fields[0]}:{fields[1][:8]}...:{":".join(fields[2:])} {ret_pw_info}'

            raw_data = f'# cat {files_to_check}\n...\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4521(logfile):
    item_no = '4.5.2.1'
    item_title = 'Ensure default group for the root account is GID 0'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/passwd'

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#'):
                    continue

                fields = line.strip().split(':')
                gid = fields[3]
                if fields[0] == 'root' and gid == '0':
                    result_code = 0
                    raw_data += f'[ok] {line.strip()} --> `root: gid 0`\n'
                else:
                    raw_data += f'[vul] {line.strip()}--> `root: gid not 0`\n'
                break
            raw_data = f'# cat {files_to_check}\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4522(logfile):
    item_no = '4.5.2.2'
    item_title = 'Ensure root user umask is configured'
    result_code = 1
    raw_data = ''
    files_to_check = ['/root/.bash_profile', '/root/.bashrc', '/etc/login.defs']
    regex_pattern = re.compile(r'^[ \t]*(export[ \t]*)?umask([ \t]*=[ \t]*(\d{3,4})|[ \t]*(\d{3,4}))', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 2
    allowed_values = ['0027', '0022', '022', '027']
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if is_not_vulnerable >= 1:
            break
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)

                if ret_sp_value:
                    ret_sp_value = ret_sp_value.strip()
                    if ret_sp_value in allowed_values:
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] Found: {file}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {file}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {file}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{file}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4523(logfile):
    item_no = '4.5.2.3'
    item_title = 'Ensure system accounts are secured'
    result_code = 2
    raw_data = ''
    files_to_check = '/etc/passwd'

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#') or len(line.strip()) == 0:
                    continue

                fields = line.strip().split(':')
                if fields[0] in ['root', 'halt', 'sync', 'shutdown', 'nfsnobody']:
                    continue

                if fields[-1] in ['/sbin/nologin', '/usr/sbin/nologin']:
                    continue

                raw_data += f'[manual] {line.strip()}\n'
            raw_data = f'# cat {files_to_check}\n{raw_data}'

        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4524(logfile):
    item_no = '4.5.2.4'
    item_title = 'Ensure root password is set'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/shadow'

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#'):
                    continue

                fields = line.strip().split(':')
                if fields[0] == 'root' and fields[1] and not fields[1].startswith(('*', '!')):
                    result_code = 0
                    raw_data += f'[ok] {fields[0]}:{fields[1][:8]}...{":".join(fields[2:])}\n'
                else:
                    raw_data += f'[vul] {fields[0]}:{fields[1][:8]}...{":".join(fields[2:])}\n'
                break
            raw_data = f'# cat {files_to_check}\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4531(logfile):
    item_no = '4.5.3.1'
    item_title = 'Ensure nologin is not listed in /etc/shells'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/shells'
    search_string = 'nologin'

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for line in file_content:
                if line.startswith('#') or len(line.strip()) == 0:
                    continue

                line_stripped = line.replace('/', '').strip()
                if line_stripped == search_string:
                    result_code = 0
                    raw_data += f'{line.strip()} --> `[ok]`\n'
                else:
                    raw_data += f'{line.strip()}\n'
            raw_data = f'# cat {files_to_check}\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4532(logfile):
    item_no = '4.5.3.2'
    item_title = 'Ensure default user shell timeout is configured'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/bashrc', '/etc/profile']
    dirs_to_check = '/etc/profile.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.sh'):
                    files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[ \t]*(export[ \t]*|readonly[ \t]*)?TMOUT=[ \t]*(\d{3,4})', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 2
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if is_not_vulnerable >= 1:
            break
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    ret_sp_value = int(ret_sp_value)
                    if 0 < ret_sp_value <= 900:
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] Found: {file}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {file}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {file}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[vul] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{file}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def d4533(logfile):
    item_no = '4.5.3.3'
    item_title = 'Ensure default user umask is configured'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/profile', '/etc/bashrc', '/etc/bash.bashrc',
                      '/etc/login.defs', '/etc/default/login', '/etc/pam.d/postlogin']
    dirs_to_check = '/etc/profile.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.sh'):
                    files_to_check.append(os.path.join(root, file))

    files_to_check_dict = {}
    regex_default = r'^[ \t]*(export[ \t]*)?umask([ \t]*=[ \t]*(\d{3,4})|[ \t]*(\d{3,4}))'
    regex_pam = r'^[ \t]*session[ \t]+[^#\n\r]+[ \t]*pam_umask\.so[ \t]*([^#\n\r]+[ \t]*)?umask=(0?[0-7][2-7]7)\b'

    for file in files_to_check:
        if file == '/etc/pam.d/postlogin':
            files_to_check_dict[file] = regex_pam
        else:
            files_to_check_dict[file] = regex_default

    allowed_values = ['027', '077', 'u=rwx,g=rx,o=r']

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_vulnerable = 0
    is_vulnerable_values = []
    is_not_vulnerable_values = []

    for key, value in files_to_check_dict.items():
        if os.path.exists(key):
            is_file_found += 1
            try:
                regex_pattern = re.compile(f'{value}', re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(key, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    ret_sp_value = ret_sp_value.split('=')
                    if len(ret_sp_value) == 1:
                        ret_sp_value = ret_sp_value[0].split()
                    ret_sp_value = ret_sp_value[1]

                    if ret_sp_value in allowed_values:
                        is_not_vulnerable_values.append(key)
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        is_vulnerable += 1
                        is_vulnerable_values.append(key)
                        raw_data += (f'[vul] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                else:
                    is_vulnerable += 1
                    raw_data += (f'[vul] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'

    if is_vulnerable == 0:
        result_code = 0
    if is_file_found == 0:
        result_code = 2
    if result_code == 1:
        raw_data = (f'{raw_data}\n'
                    f'- umask is set correctly: {is_not_vulnerable_values}\n'
                    f'- umask is set incorrectly: {is_vulnerable_values}')

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def e5111(logfile):
    item_no = '5.1.1.1'
    item_title = 'Ensure rsyslog is installed'
    result_code = 1
    pkg_name = 'rsyslog'
    cmd = ['rpm', '-qa', pkg_name]

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        if ret_cmd_result:
            result_code = 0
            raw_data = (f'[ok] Found: {pkg_name}\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result.strip()}')
        else:
            raw_data = f'[vul] Not Found: {pkg_name}\n'
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def e5112(logfile):
    item_no = '5.1.1.2'
    item_title = 'Ensure rsyslog service is enabled'
    result_code = 2
    raw_data = ''
    is_not_vulnerable = 0
    is_vulnerable = 0

    service_names = ['rsyslog.service']
    services_info = check_service_info(service_names)

    if services_info:
        for service_name, info in services_info.items():
            if info["active_status"] == 'inactive' and info["enable_status"] == 'disabled':
                is_vulnerable += 1
                raw_data += (f'[vul] Not in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
            else:
                is_not_vulnerable += 1
                raw_data += (f'[ok] in use: {service_name}\n'
                             f'# systemctl is-enabled {service_name}\n{info["enable_status"]}\n\n'
                             f'# systemctl is-active {service_name}\n{info["active_status"]}\n')
                raw_data += f'\n- PID: {info["run_pid"]}\n'
                if info["binding_info"]:
                    raw_data += f'- Binding\n`````\n{info["binding_info"]}\n`````\n'

            if len(service_names) >= 2:
                raw_data = f'{raw_data}\n\n'
        if is_vulnerable == len(service_names):
            result_code = 1
        if is_not_vulnerable == len(service_names):
            result_code = 0
    else:
        result_code = 3
        raw_data = f'[error] Fail to get services `{service_names}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def e5114(logfile):
    item_no = '5.1.1.4'
    item_title = 'Ensure rsyslog default file permissions are configured'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/rsyslog.conf']
    dirs_to_check = '/etc/rsyslog.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[ \t]*\$FileCreateMode[ \t]*(\d{3,4})[ \t]*(#.*)?$', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 1
    allowed_values = ['0640', '0600']
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if is_not_vulnerable >= 1:
            break
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    if str(ret_sp_value) in allowed_values:
                        is_not_vulnerable += 1
                        raw_data += (f'[ok] Found: {file}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {file}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[vul] Found: {file}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[ok] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def e5115(logfile):
    item_no = '5.1.1.5'
    item_title = 'Ensure logging is configured'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/rsyslog.conf']
    dirs_to_check = '/etc/rsyslog.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    regex_pattern = re.compile(r'^[^\s#]+\s+[/:-]\S*', re.IGNORECASE)
    regex_type = 'match'
    regex_match = 0
    is_file_found = 0
    is_not_vulnerable = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                    = grep_search_pattern(file, True, False, regex_type, regex_pattern, regex_match)
                if ret_sp_value:
                    is_not_vulnerable += 1
                    ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                    ret_sp_value = re.sub(r'(?<=\S)\s+(?=\S)', ' ', ret_sp_value)
                    raw_data += (f'[ok] Found: {file}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                                 f'# cat {file}\n...\n{ret_sp_value_contexts}')
                else:
                    raw_data += (f'[manual] Not Found: {file} --> {regex_pattern.pattern}\n\n'
                                 f'# cat {file}\n...\n{"".join(ret_raw_file_contents)}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            result_code = 2
            raw_data += f'[ok] No such file or directory: `{file}`\n'

    if is_not_vulnerable >= 1:
        result_code = 0
    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def e5116(logfile):
    item_no = '5.1.1.6'
    item_title = 'Ensure rsyslog is configured to send logs to a remote log host'
    result_code = 2
    raw_data = ''
    files_to_check = ['/etc/rsyslog.conf']
    dirs_to_check = '/etc/rsyslog.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    regex_patterns = [
        r'^[ \t]*[^I][^I]*@',
        r'^[ \t]*([^#]+[ \t]+)?action\(([^#]+[ \t]+)?target="?[^#"\s]+("?)[ \t]*'
    ]

    files_to_check_dict = {file: regex_patterns for file in files_to_check}

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0

    for key, values in files_to_check_dict.items():
        for value in values:
            if os.path.exists(key):
                is_file_found += 1
                try:
                    regex_pattern = re.compile(value, re.IGNORECASE)
                    ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                        = grep_search_pattern(key, True, False, regex_type, regex_pattern, regex_match)
                    if ret_sp_value:
                        ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                        ret_sp_value = re.sub(r'(?<=\S)\s+(?=\S)', ' ', ret_sp_value)
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[ok] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                     f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}')
                    raw_data = f'{raw_data}\n\n'
                except Exception as error:
                    result_code = 3
                    raw_data = f'{str(error)}'
            else:
                result_code = 2
                raw_data += f'[ok] No such file or directory: `{key}`\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def e5117(logfile):
    item_no = '5.1.1.7'
    item_title = 'Ensure rsyslog is not configured to receive logs from a remote client'
    result_code = 2
    raw_data = ''
    files_to_check = ['/etc/rsyslog.conf']
    dirs_to_check = '/etc/rsyslog.d/'

    if os.path.isdir(dirs_to_check):
        for root, _, files in os.walk(dirs_to_check):
            for file in files:
                if file.endswith('.conf'):
                    files_to_check.append(os.path.join(root, file))

    regex_patterns = [
        r'^[ \t]*module\(load="(imtcp|imudp)"\)',
        r'^[ \t]*input\(type="(imtcp|imudp)"[ \t]*port="(\d+)"\)',
        r'^[ \t]*\$ModLoad[ \t]*(imtcp|imudp)$',
        r'^[ \t]*\$(UDPServerRun|InputTCPServerRun|InputTCPMaxSessions)[ \t]*(\d+)'

    ]

    files_to_check_dict = {file: regex_patterns for file in files_to_check}

    regex_type = 'match'
    regex_match = 0
    is_file_found = 0

    for key, values in files_to_check_dict.items():
        for value in values:
            if os.path.exists(key):
                is_file_found += 1
                try:
                    regex_pattern = re.compile(value, re.IGNORECASE)
                    ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, ret_raw_file_contents \
                        = grep_search_pattern(key, True, False, regex_type, regex_pattern, regex_match)
                    if ret_sp_value:
                        ret_sp_value_count = 'and more..' if len(ret_sp_value_context_num.split(',')) > 1 else ''
                        ret_sp_value = re.sub(r'(?<=\S)\s+(?=\S)', ' ', ret_sp_value)
                        raw_data += (f'[ok] Found: {key}\n'
                                     f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                     f'{ret_sp_value_count} near at line: {ret_sp_value_context_num}\n\n'
                                     f'# cat {key}\n...\n{ret_sp_value_contexts}')
                    else:
                        raw_data += (f'[ok] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                     f'# cat {key}\n...\n{"".join(ret_raw_file_contents)}')
                    raw_data = f'{raw_data}\n\n'
                except Exception as error:
                    result_code = 3
                    raw_data = f'{str(error)}'
            else:
                result_code = 2
                raw_data += f'[ok] No such file or directory: `{key}`\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f611(logfile):
    item_no = '6.1.1'
    item_title = 'Ensure permissions on /etc/passwd are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/passwd'
    allowed_values = [600, 644, 400, 440, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f612(logfile):
    item_no = '6.1.2'
    item_title = 'Ensure permissions on /etc/passwd- are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/passwd-'
    allowed_values = [600, 644, 400, 440, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f613(logfile):
    item_no = '6.1.3'
    item_title = 'Ensure permissions on /etc/opasswd are configured'
    result_code = 1
    raw_data = ''
    files_to_check = ['/etc/security/opasswd', '/etc/security/opasswd.old']
    allowed_values = [600, 400, 'root:root']
    is_file_found = 0

    for file in files_to_check:
        if os.path.exists(file):
            is_file_found += 1
            try:
                ret_perms_value = filepath_get_perms_value(file)
                ret_owner_group_value = filepath_get_owner_group(file)
                if ret_perms_value is not None and ret_owner_group_value is not None:
                    if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                        result_code = 0
                        raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                     f'- permissions: {ret_perms_value}\n'
                                     f'- owner:group: {ret_owner_group_value}')
                    else:
                        raw_data += (f'[vul] {filepath_ls_al(file)}\n'
                                     f'- permissions: {ret_perms_value}\n'
                                     f'- owner:group: {ret_owner_group_value}')
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
        else:
            raw_data += f'[manual] No such file or directory: `{file}`\n'

    if is_file_found == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f614(logfile):
    item_no = '6.1.4'
    item_title = 'Ensure permissions on /etc/group are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/group'
    allowed_values = [600, 644, 400, 440, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f615(logfile):
    item_no = '6.1.5'
    item_title = 'Ensure permissions on /etc/group- are configured '
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/group-'
    allowed_values = [600, 644, 400, 440, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f616(logfile):
    item_no = '6.1.6'
    item_title = 'Ensure permissions on /etc/shadow are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/shadow'
    valid_perms = 0
    allowed_values = ['root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if (ret_perms_value == valid_perms) and (ret_owner_group_value in allowed_values):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data += f'[Error] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f617(logfile):
    item_no = '6.1.7'
    item_title = 'Ensure permissions on /etc/shadow- are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/shadow-'
    valid_perms = 0
    allowed_values = ['root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if (ret_perms_value == valid_perms) and (ret_owner_group_value in allowed_values):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data += f'[Error] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f618(logfile):
    item_no = '6.1.8'
    item_title = 'Ensure permissions on /etc/gshadow are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/gshadow'
    valid_perms = 0
    allowed_values = ['root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if (ret_perms_value == valid_perms) and (ret_owner_group_value in allowed_values):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data += f'[Error] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f619(logfile):
    item_no = '6.1.9'
    item_title = 'Ensure permissions on /etc/gshadow- are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/gshadow-'
    valid_perms = 0
    allowed_values = ['root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if (ret_perms_value == valid_perms) and (ret_owner_group_value in allowed_values):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 3
        raw_data += f'[Error] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f6110(logfile):
    item_no = '6.1.10'
    item_title = 'Ensure permissions on /etc/shells are configured'
    result_code = 1
    raw_data = ''
    files_to_check = '/etc/shells'
    allowed_values = [600, 644, 400, 440, 'root:root']

    if os.path.exists(files_to_check):
        try:
            ret_perms_value = filepath_get_perms_value(files_to_check)
            ret_owner_group_value = filepath_get_owner_group(files_to_check)
            if ret_perms_value is not None and ret_owner_group_value is not None:
                if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                    result_code = 0
                    raw_data += (f'[ok] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
                else:
                    raw_data += (f'[vul] {filepath_ls_al(files_to_check)}\n'
                                 f'- permissions: {ret_perms_value}\n'
                                 f'- owner:group: {ret_owner_group_value}')
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f6111(logfile):
    item_no = '6.1.11'
    item_title = 'Ensure world writable files and directories are secured'
    result_code = 2
    # find / -path /proc -prune -o \( -perm -2 -a \( -type f -o -type d \) -a -size +0c \) -exec ls -ldb {} \;
    cmd = ['find', '/', '-path', '/proc', '-prune', '-o', '(', '-perm', '-2', '-a', '(', '-type', 'f', '-o',
           '-type', 'd', ')', '-a', '-size', '+0c', ')', '-exec', 'ls', '-ldb', '{}', ';']

    message = ('********************************************************\n'
               f'This Audit item use "{cmd[0]}" command to improve scan speed.\n'
               '********************************************************\n')

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        if ret_cmd_result:
            raw_data = (f'[manual] Found: world writable files and directories\n\n{message}\n\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result}')
        else:
            result_code = 0
            raw_data = ('[ok] Not Found: world writable files and directories\n\n'
                        f'# {" ".join(cmd)}\n')
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f6112(logfile):
    item_no = '6.1.12'
    item_title = 'Ensure no unowned or ungrouped files or directories exist'
    result_code = 2
    # find / \( -path /proc -prune \) -o \( -nouser -o -nogroup \) -exec ls -ldb {} \;
    cmd = ['find', '/', '-path', '/proc', '-prune', '-o', '-nouser', '-o', '-nogroup',
           '-exec', 'ls', '-ldb', '{}', ';']

    message = ('********************************************************\n'
               f'This Audit item use "{cmd[0]}" command to improve scan speed.\n'
               '********************************************************\n')

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        if ret_cmd_result:
            raw_data = (f'[manual] Found: no unowned or ungrouped files or directories\n{message}\n\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result}')
        else:
            result_code = 0
            raw_data = ('[ok] Not Found: no unowned or ungrouped files or directories\n\n'
                        f'# {" ".join(cmd)}\n')
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f6113(logfile):
    item_no = '6.1.13'
    item_title = 'Ensure SUID and SGID files are reviewed'
    result_code = 2
    # find / -xdev -user root \( -perm -4000 -o -perm -2000 \) -exec ls -ldb {} \;
    cmd = ['find', '/', '-xdev', '-user', 'root', '-perm', '-4000', '-o', '-perm', '-2000',
           '-exec', 'ls', '-ldb', '{}', ';']

    message = ('********************************************************\n'
               f'This Audit item use "{cmd[0]}" command to improve scan speed.\n'
               '********************************************************\n')

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        if ret_cmd_result:
            raw_data = (f'[manual] Found: SUID and SGID files\n{message}\n\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result}')
        else:
            result_code = 0
            raw_data = ('[ok] Not Found: SUID and SGID files\n\n'
                        f'# {" ".join(cmd)}\n')
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f6114(logfile):
    item_no = '6.1.14'
    item_title = 'Audit system file permissions'
    result_code = 2
    # rpm -Va --nomtime --nosize --nomd5 --nolinkto --noconfig --noghost
    cmd = ['rpm', '-Va', '--nomtime', '--nosize', '--nomd5', '--nolinkto', '--noconfig', '--noghost']
    message = """
**************************************
Code    Meaning
S       File size differs.
M       File mode differs (includes permissions and file type).
D       Device file major/minor number mismatch.
L       readLink(2) path mismatch.
U       User ownership differs.
G       Group ownership differs.
T       The file time (mtime) differs.
P       Capabilities differ.
**************************************
"""
    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)
    if ret_cmd_status == '[ok]':
        if ret_cmd_result:
            raw_data = (f'[manual] Found: Check Manually\n\n{message}\n\n'
                        f'# {" ".join(cmd)}\n{ret_cmd_result}')
        else:
            result_code = 0
            raw_data = ('[ok] No issues found.\n\n'
                        f'# {" ".join(cmd)}\n')
    else:
        raw_data = (f'[manual] Found: Check Manually\n\n{message}\n\n'
                    f'# {" ".join(cmd)}\n{ret_cmd_result}')

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f621(logfile):
    item_no = '6.2.1'
    item_title = 'Ensure accounts in /etc/passwd use shadowed passwords'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/passwd'

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                fields = line.strip().split(':')
                if fields[1] == 'x':
                    raw_data += f'[ok] {line.strip()}\n'
                else:
                    result_code = 1
                    raw_data += f'[vul] {line.strip()} --> `Found`: Not Shadow Password\n'

            raw_data = f'# cat {files_to_check}\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f622(logfile):
    item_no = '6.2.2'
    item_title = 'Ensure /etc/shadow password fields are not empty'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/shadow'

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                fields = line.strip().split(':')
                if len(fields[1]) == 0:
                    result_code = 1
                    raw_data += f'[vul] {fields[0]}:NO-PASSWORD:{":".join(fields[2:])} --> `Found`: No Password\n'
                else:
                    raw_data += f'[ok] {fields[0]}:{fields[1][:8]}...:{":".join(fields[2:])}\n'

            raw_data = f'# cat {files_to_check}\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f623(logfile):
    item_no = '6.2.3'
    item_title = 'Ensure all groups in /etc/passwd exist in /etc/group'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/passwd'
    etc_group = '/etc/group'

    if os.path.exists(files_to_check):
        try:
            gid_dict = {}
            with open(etc_group, 'r', encoding='utf-8') as gf:
                for line in gf:
                    fields = line.strip().split(':')
                    if len(fields) > 2:
                        gid = fields[2]
                        gid_dict[gid] = line.strip()

            with open(files_to_check, 'r', encoding='utf-8') as pf:
                passwd_content = pf.readlines()

            for line in passwd_content:
                if line.startswith('#') or len(line.strip()) == 0:
                    continue
                fields = line.strip().split(':')
                if len(fields) > 3:
                    group_id = fields[3]
                    if group_id in gid_dict:
                        raw_data += f'[ok] {line.strip()} --> {etc_group} {gid_dict[group_id]}\n'
                    else:
                        result_code = 1
                        raw_data += f'[vul] {line.strip()} --> `Not found`: GID {group_id} in {etc_group}\n'

            raw_data = f'# cat {files_to_check}\n{raw_data}'

        except Exception as error:
            result_code = 3
            raw_data = f'Error: {str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f624(logfile):
    item_no = '6.2.4'
    item_title = 'Ensure no duplicate UIDs exist'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/passwd'
    uid_dict = {}

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#') or len(line.strip()) == 0:
                    continue

                fields = line.strip().split(':')
                uid = fields[2]
                if uid in uid_dict:
                    raw_data += f'[vul] {uid_dict[uid]}\n'
                    raw_data += f'[vul] {line.strip()}\n'
                    result_code = 1
                else:
                    uid_dict[uid] = line.strip()

            if result_code == 0:
                raw_data = ''.join(f"[ok] {value}\n" for value in uid_dict.values())
            raw_data = f'# cat {files_to_check}\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f625(logfile):
    item_no = '6.2.5'
    item_title = 'Ensure no duplicate GIDs exist'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/group'
    gid_dict = {}

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#') or len(line.strip()) == 0:
                    continue

                fields = line.strip().split(':')
                gid = fields[2]
                if gid in gid_dict:
                    raw_data += f'[vul] {gid_dict[gid]}\n'
                    raw_data += f'[vul] {line.strip()}\n'
                    result_code = 1
                else:
                    gid_dict[gid] = line.strip()

            if result_code == 0:
                raw_data = ''.join(f"[ok] {value}\n" for value in gid_dict.values())
            raw_data = f'# cat {files_to_check}\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f626(logfile):
    item_no = '6.2.6'
    item_title = 'Ensure no duplicate user names exist'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/passwd'
    username_dict = {}

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#') or len(line.strip()) == 0:
                    continue

                fields = line.strip().split(':')
                username = fields[0]
                if username in username_dict:
                    raw_data += f'[vul] {username_dict[username]}\n'
                    raw_data += f'[vul] {line.strip()}\n'
                    result_code = 1
                else:
                    username_dict[username] = line.strip()

            if result_code == 0:
                raw_data = ''.join(f"[ok] {value}\n" for value in username_dict.values())
            raw_data = f'# cat {files_to_check}\n...\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f627(logfile):
    item_no = '6.2.7'
    item_title = 'Ensure no duplicate group names exist'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/group'
    groupname_dict = {}

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#') or len(line.strip()) == 0:
                    continue

                fields = line.strip().split(':')
                groupname = fields[0]
                if groupname in groupname_dict:
                    raw_data += f'[vul] {groupname_dict[groupname]}\n'
                    raw_data += f'[vul] {line.strip()}\n'
                    result_code = 1
                else:
                    groupname_dict[groupname] = line.strip()

            if result_code == 0:
                raw_data = ''.join(f"[ok] {value}\n" for value in groupname_dict.values())
            raw_data = f'# cat {files_to_check}\n...\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f628(logfile):
    item_no = '6.2.8'
    item_title = 'Ensure root path integrity'
    result_code = 1
    raw_data = ''
    cmd_result = ''
    cmd = ['sudo', '-Hiu', 'root', 'env']
    files_to_check = []

    allowed_values = [750, 700, 555, 'root:root']

    regex_type = 'search'
    regex_match = 0
    cmd_result_check_dict = {
        'Check for Empty Directory Paths': r'::',
        'Check for Trailing Colon ': r':[ \t]*$',
        'Check for Current Working Directory': r'([ \t]+|:)\.(:|[ \t]*$)'
    }

    is_file_found = 0
    is_not_vulnerable = 0

    ret_cmd_status, ret_cmd_result = subprocess_cmd_execute(cmd)

    if ret_cmd_status == '[ok]':
        ret_cmd_result_lines = ret_cmd_result.splitlines()
        for line in ret_cmd_result_lines:
            if line.startswith('PATH='):
                cmd_result = line.split('=')[1]
                break
    else:
        result_code = 3
        raw_data = f'{ret_cmd_result}\n'

    if cmd_result:
        for path in cmd_result.split(':'):
            if len(path) == 0:
                continue
            files_to_check.append(path)

        # root path directories permission check
        for file in files_to_check:
            if os.path.exists(file):
                is_file_found += 1
                try:
                    ret_perms_value = filepath_get_perms_value(file)
                    ret_owner_group_value = filepath_get_owner_group(file)
                    if ret_perms_value is not None and ret_owner_group_value is not None:
                        if all(value in allowed_values for value in [ret_perms_value, ret_owner_group_value]):
                            is_not_vulnerable += 1
                            raw_data += (f'[ok] {filepath_ls_al(file)}\n'
                                         f'- permissions: {ret_perms_value}\n'
                                         f'- owner:group: {ret_owner_group_value}')
                        else:
                            raw_data += (f'[vul] {filepath_ls_al(file)}\n'
                                         f'- permissions: {ret_perms_value}\n'
                                         f'- owner:group: {ret_owner_group_value}')
                        raw_data = f'{raw_data}\n\n'
                except Exception as error:
                    result_code = 3
                    raw_data += f'{str(error)}'
            else:
                raw_data += f'[manual] No such file or directory: `{file}`\n\n'

    if files_to_check:
        if raw_data:
            raw_data = f'{raw_data}\n\n'

        # root path validation check
        for key, value in cmd_result_check_dict.items():
            try:
                regex_pattern = re.compile(value, re.IGNORECASE)
                ret_sp_value, ret_sp_value_contexts, ret_sp_value_context_num, _ \
                    = grep_search_pattern(cmd_result, False, True, regex_type, regex_pattern, regex_match)
                if ret_sp_value is not None:
                    raw_data += (f'[vul] Found: {key}\n'
                                 f'- found: {regex_pattern.pattern} --> `{ret_sp_value}` '
                                 f'near at line: {ret_sp_value_context_num}\n\n'
                                 f'# {" ".join(cmd)} | grep "^PATH" | cut -d= -f2\n...\n{ret_sp_value_contexts}')
                else:
                    is_not_vulnerable += 1
                    raw_data += (f'[ok] Not Found: {key} --> {regex_pattern.pattern}\n\n'
                                 f'# {" ".join(cmd)} | grep "^PATH" | cut -d= -f2\n...\n{cmd_result}')
                raw_data = f'{raw_data}\n\n'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'

    if is_not_vulnerable == 0:
        result_code = 0
    if is_file_found == 0 and is_not_vulnerable == 0:
        result_code = 2

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f629(logfile):
    item_no = '6.2.9'
    item_title = 'Ensure root is the only UID 0 account'
    result_code = 0
    raw_data = ''
    files_to_check = '/etc/passwd'

    if os.path.exists(files_to_check):
        try:
            with open(files_to_check, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#'):
                    continue

                fields = line.strip().split(':')
                uid = fields[2]
                if fields[0] == 'root' and uid == '0':
                    raw_data += f'[ok] {line.strip()} --> `root`: uid 0\n'
                elif fields[0] != 'root' and uid == '0':
                    result_code = 1
                    raw_data += f'[vul] {line.strip()} --> `other root`: uid 0\n'
                else:
                    raw_data += f'[ok] {line.strip()}\n'
            raw_data = f'# cat {files_to_check}\n...\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f6210(logfile):
    item_no = '6.2.10'
    item_title = 'Ensure local interactive user home directories are configured'
    result_code = 0
    raw_data = ''
    etc_shells = '/etc/shells'
    files_to_check = '/etc/passwd'
    shell_lists = []
    allowed_values = [700, 750, 500, 550]

    if os.path.exists(files_to_check):
        try:
            with open(etc_shells, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('#') or len(line.strip()) == 0:
                        continue
                    if 'nologin' not in line.strip():
                        shell_lists.append(line.strip())
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'

        if shell_lists:
            try:
                with open(files_to_check, 'r', encoding='utf-8') as f:
                    file_content = f.readlines()

                for i, line in enumerate(file_content):
                    if line.startswith('#') or len(line.strip()) == 0:
                        continue

                    fields = line.strip().split(':')
                    if fields[-1] in shell_lists:
                        if len(fields[5]) == 0:
                            result_code = 1
                            raw_data += f'[vul] {line.strip()} --> [ Not assign home directory: Error ]\n'
                        elif not os.path.exists(fields[5]):
                            result_code = 1
                            raw_data += f'[vul] {line.strip()} --> [ Directory not exists: {fields[5]} ]\n'
                        else:
                            ret_value = filepath_get_perms_value(fields[5])
                            if ret_value not in allowed_values:
                                result_code = 1  # 취약
                                raw_data += f'[vul] {line.strip()} --> [ {ret_value}:{fields[5]} ]\n'
                            else:
                                raw_data += f'[ok] {line.strip()} --> [ {ret_value}:{fields[5]} ]\n'

                raw_data = f'# cat {files_to_check}\n...\n{raw_data}'
            except Exception as error:
                result_code = 3
                raw_data = f'{str(error)}'
    else:
        result_code = 2
        raw_data += f'[manual] No such file or directory: `{files_to_check}`\n'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def f6211(logfile):
    item_no = '6.2.11'
    item_title = 'Ensure local interactive user dot files access is configured'
    result_code = 0
    raw_data = ''
    etc_shells = '/etc/shells'
    etc_passwd = '/etc/passwd'
    shell_lists = []

    files_to_check = {
        '.ssh': [700],
        '.ssh/id_rsa': [600, 400],
        '.ssh/authorized_keys': [600, 400],
        '.history': [600, 400],
        '.sh_history': [600, 400],
        '.k5login': [400],
        '.rhosts': [400, 600, 644],
        '.profile': [600, 644],
        '.dtprofile': [600, 644],
        '.google_authenticator': [400],
        '.viminfo': [600, 400],
        '.cshrc': [600, 644],
        '.kshrc': [600, 644],
        '.tcshrc': [600, 644],
        '.bash_history': [600, 400],
        '.bash_profile': [600, 644],
        '.bashrc': [600, 644],
        '.bash_login': [600, 644],
        '.bash_logout': [600, 644],
        '.exrc': [600, 400],
        '.netrc': [600, 400]
    }

    try:
        with open(etc_shells, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('#') or len(line.strip()) == 0:
                    continue
                if 'nologin' not in line.strip():
                    shell_lists.append(line.strip())
    except Exception as error:
        result_code = 3
        raw_data = f'{str(error)}'

    if shell_lists:
        try:
            with open(etc_passwd, 'r', encoding='utf-8') as f:
                file_content = f.readlines()

            for i, line in enumerate(file_content):
                if line.startswith('#') or len(line.strip()) == 0:
                    continue

                fields = line.strip().split(':')

                if fields[0] in ['halt', 'sync', 'shutdown', 'nfsnobody']:
                    continue

                if len(fields[5]) == 0:
                    continue

                if fields[-1] in shell_lists:
                    for key, value in files_to_check.items():
                        file_path = os.path.join(fields[5], key)
                        ret_perms_value = filepath_get_perms_value(file_path)
                        ret_check_status = filepath_check_perms(file_path, value)
                        if ret_check_status:
                            if ret_check_status == '[vul]':
                                result_code = 1
                            raw_data += f'{ret_check_status} {":".join(fields[:4])}:... --> [ {ret_perms_value}:{file_path} ]\n'
            if raw_data:
                raw_data = f'# cat {etc_passwd}\n...\n{raw_data}'
        except Exception as error:
            result_code = 3
            raw_data = f'{str(error)}'

    show_result(item_no, item_title, get_result(result_code))
    log_data = log_contents(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            item_no, item_title, get_result(result_code), result_code, raw_data)
    export_result(logfile, log_data)


def main():
    home_path = os.path.dirname(os.path.realpath(__file__))
    logfile = os.path.join(home_path, f'{int(datetime.utcnow().timestamp())}_{get_hostname()}_audit.xml')

    check_logfile(logfile)
    logo()
    print('')
    print(f'[+][{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] Start Security Audit.')
    print('---------------------------------------------------------')
    print('')
    try:
        is_valid_command, result_data = verify_required_commands()
        if not is_valid_command:
            print(f'This tool requires commands that do not exist on this system: {result_data}')
            print('Please ensure the necessary commands are installed and try running the script again.')
            error_commands_check(logfile, result_data)
            return

        is_valid_sudo = verify_sudo_privileges()
        if not is_valid_sudo:
            error_sudo_privileges(logfile)
            print('This tool requires sudo privileges. Please run it with sudo privileges.')
            return

        _, _, os_name = get_os_release()
        print(f' Hostname: {get_hostname()}')
        print(f' OS: {os_name}')
        print(f' IP Address: {get_ip_addresses()}')
        print(f' MAC Address: {get_mac_addresses()}')
        print('')

        print('[+] 1.Initial Setup')
        print('---------------------------------------------------------')
        print(' 1.6.Configure system wide crypto policy')
        a161(logfile)
        a162(logfile)
        a163(logfile)
        a164(logfile)
        print('')
        print(' 1.7.Configure Command Line Warning Banners')
        a171(logfile)
        a172(logfile)
        a173(logfile)
        a174(logfile)
        a175(logfile)
        a176(logfile)

        print('')
        print('[+] 2.Services')
        print('---------------------------------------------------------')
        print(' 2.1.Configure Time Synchronization')
        b211(logfile)
        b212(logfile)
        b213(logfile)
        print('')
        print(' 2.2.Configure Special Purpose Services')
        b221(logfile)
        b222(logfile)
        b223(logfile)
        b224(logfile)
        b225(logfile)
        b226(logfile)
        b227(logfile)
        b228(logfile)
        b229(logfile)
        b2210(logfile)
        b2211(logfile)
        b2212(logfile)
        b2213(logfile)
        b2214(logfile)
        b2215(logfile)
        b2216(logfile)
        b2217(logfile)
        b2218(logfile)
        b2219(logfile)
        b2220(logfile)
        b2221(logfile)
        b2222(logfile)

        print('')
        print('[+] 4.Access, Authentication and Authorization')
        print('---------------------------------------------------------')
        print(' 4.1.Configure job schedulers')
        print('  4.1.1.Configure cron')
        d4111(logfile)
        d4112(logfile)
        d4113(logfile)
        d4114(logfile)
        d4115(logfile)
        d4116(logfile)
        d4117(logfile)
        d4118(logfile)
        print('')
        print('  4.1.2.Configure at')
        d4121(logfile)
        print('')
        print(' 4.2.Configure SSH Server')
        d421(logfile)
        d422(logfile)
        d423(logfile)
        d424(logfile)
        d425(logfile)
        d426(logfile)
        d427(logfile)
        d428(logfile)
        d429(logfile)
        d4210(logfile)
        d4211(logfile)
        d4212(logfile)
        d4213(logfile)
        d4214(logfile)
        d4215(logfile)
        d4216(logfile)
        d4217(logfile)
        d4218(logfile)
        d4219(logfile)
        d4220(logfile)
        d4221(logfile)
        d4222(logfile)
        print('')
        print(' 4.3.Configure privilege escalation')
        d431(logfile)
        d432(logfile)
        d433(logfile)
        d434(logfile)
        d435(logfile)
        d436(logfile)
        d437(logfile)
        print('')
        print(' 4.4.Configure Pluggable Authentication Modules')
        print('  4.4.2.Configure authselect')
        d4421(logfile)
        d4422(logfile)
        d4423(logfile)
        d4424(logfile)
        d4425(logfile)
        print('')
        print('  4.4.3.Configure pluggable module arguments')
        print('  4.4.3.1.Configure pam_faillock module')
        d44311(logfile)
        d44312(logfile)
        d44313(logfile)
        print('')
        print('  4.4.3.2.Configure pam_pwquality module')
        d44321(logfile)
        d44322(logfile)
        d44323(logfile)
        d44324(logfile)
        d44325(logfile)
        d44326(logfile)
        d44327(logfile)
        print('')
        print('  4.4.3.3.Configure pam_pwhistory module')
        d44331(logfile)
        d44332(logfile)
        d44333(logfile)
        print('')
        print('  4.4.3.4.Configure pam_unix module')
        d44341(logfile)
        d44342(logfile)
        d44343(logfile)
        d44344(logfile)
        print('')
        print(' 4.5.User Accounts and Environment')
        print('  4.5.1.Configure shadow password suite parameters')
        d4511(logfile)
        d4512(logfile)
        d4513(logfile)
        d4514(logfile)
        d4515(logfile)
        print('')
        print('  4.5.2.Configure root and system accounts and environment')
        d4521(logfile)
        d4522(logfile)
        d4523(logfile)
        d4524(logfile)
        print('')
        print('  4.5.3.Configure user default environment')
        d4531(logfile)
        d4532(logfile)
        d4533(logfile)

        print('')
        print('[+] 5.Logging and Auditing')
        print('---------------------------------------------------------')
        print(' 5.1.Configure Logging')
        print('  5.1.1.Configure rsyslog')
        e5111(logfile)
        e5112(logfile)
        e5114(logfile)
        e5115(logfile)
        e5116(logfile)
        e5117(logfile)

        print('')
        print('[+] 6.System Maintenance')
        print('---------------------------------------------------------')
        print(' 6.1.System File Permissions')
        f611(logfile)
        f612(logfile)
        f613(logfile)
        f614(logfile)
        f615(logfile)
        f616(logfile)
        f617(logfile)
        f618(logfile)
        f619(logfile)
        f6110(logfile)
        f6111(logfile)
        f6112(logfile)
        f6113(logfile)
        f6114(logfile)

        print('')
        print(' 6.2.Local User and Group Settings')
        f621(logfile)
        f622(logfile)
        f623(logfile)
        f624(logfile)
        f625(logfile)
        f626(logfile)
        f627(logfile)
        f628(logfile)
        f629(logfile)
        f6210(logfile)
        f6211(logfile)

    finally:
        print('')
        print('[*] RESULT')
        print('---------------------------------------------------------')
        wrapping_log(logfile)
        print(f'{Bcolors.Yellow}output={logfile}{Bcolors.Endc}')
        print('---------------------------------------------------------')
        print('')
        print(f'[+][{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] End Security Audit.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f'{Bcolors.Yellow}- ::Exception:: Func:[{__name__.__name__}] '
              f'Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')
