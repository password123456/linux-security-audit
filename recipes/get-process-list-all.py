__author__ = 'https://github.com/password123456/'
__date__ = '2024.06.18'

import psutil
import socket
from datetime import datetime


def get_tty(pid):
    try:
        proc = psutil.Process(pid)
        return proc.terminal() or 'N/A'
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return 'N/A'


def get_listening_ports(pid):
    listening_ports = []
    try:
        connections = psutil.Process(pid).connections()
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                if conn.family == socket.AF_INET:
                    protocol = 'tcp'
                elif conn.family == socket.AF_INET6:
                    protocol = 'tcp6'
                elif conn.family == socket.AF_UNIX:
                    protocol = 'unix'
                else:
                    protocol = 'unknown'

                listening_ports.append(f"{protocol}://{conn.laddr.ip}:{conn.laddr.port}")

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    return listening_ports


def get_process_info():
    process_info_list = []
    for proc in psutil.process_iter(['pid', 'ppid', 'username', 'name', 'create_time', 'cmdline']):
        try:
            proc_info = proc.info
            pid = proc_info['pid']
            ppid = proc_info['ppid']
            process_account = proc_info['username']
            process_name = proc_info['name']
            create_time = datetime.fromtimestamp(proc_info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
            cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else 'N/A'
            tty = get_tty(pid)
            listen_ports = get_listening_ports(pid)
            listening_ports_str = ', '.join(listen_ports) if listen_ports else 'N/A'

            process_info_list.append((create_time, ppid, pid, process_account,
                                      process_name, tty, listening_ports_str, cmdline))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    process_info_list.sort(key=lambda x: x[1])
  
    print("{:<20} {:<8} {:<8} {:<20} {:<40} {:<10} {:<40} {:<100}"
          .format("STARTED", "PPID", "PID", "USER", "PNAME", "TTY", "LISTEN", "CMD"))

    for info in process_info_list:
        create_time, ppid, pid, process_account, process_name, tty, listening_ports_str, cmdline = info

        print("{:<20} {:<8} {:<8} {:<20} {:<40} {:<10} {:<40} {:<100}"
              .format(create_time, ppid, pid, process_account, process_name, tty, listening_ports_str, cmdline))


if __name__ == "__main__":
    get_process_info()


"""
STARTED              PPID     PID      USER                 PNAME                                    TTY        LISTEN                                   CMD                                                                                                 
2024-02-27 07:07:35  0        0        root                 kernel_task                              N/A        N/A                                      N/A                                                                                                 
2024-02-27 07:07:35  0        1        root                 launchd                                  N/A        N/A                                      N/A                                                                                                 
2024-02-27 07:07:38  1        80       root                 logd                                     N/A        N/A                                      N/A                                                                                                 
2024-02-27 07:07:39  1        82       root                 UserEventAgent                           N/A        N/A                                      N/A                                                                                                 
2024-02-27 07:07:39  1        84       root                 uninstalld                               N/A        N/A                                      N/A                                                                                                 
2024-02-27 07:07:39  1        85       root                 fseventsd                                N/A        N/A                                      N/A                                                                                                 
2024-02-27 07:07:39  1        86       root                 mediaremoted                             N/A        N/A                                      N/A                                                                                                 
2024-02-27 07:07:39  1        89       root                 systemstats                              N/A        N/A                                      N/A
...
....
........
2024-04-04 15:40:03  1        25190    drfate      Google Chrome                            N/A        tcp://127.0.0.1:50211                    /Applications/Google Chrome.app/Contents/MacOS/......
2024-06-13 11:20:46  1        81823    drfate      pycharm                                  N/A        tcp6://::127.0.0.1:63342, tcp6://::127.0.0.1:63443 /Applications/PyCharm CE.app/C.........
...
.....
........
"""
