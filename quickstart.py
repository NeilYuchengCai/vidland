#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grand Duchy of Vidland · Chancellery Quick Console

Looping menu for the four terminals. Operates ONLY on the process that
listens on the designated port (7431 by default); it never kills an
unrelated Python or browser process.

    python quickstart.py              -> looping menu
    python quickstart.py start        -> one-shot commands
    python quickstart.py stop | restart | status | open | log
"""
import os
import ssl
import sys
import time
import subprocess
import webbrowser
import urllib.request
from pathlib import Path

# Keep the console's native encoding (cp936 on a Chinese Windows console).
# Forcing UTF-8 here makes cmd render mojibake when chcp is not 65001.
try:
    sys.stdout.reconfigure(errors='replace')
except Exception:
    pass

ROOT = Path(__file__).resolve().parent
STATE = ROOT / '.workbuddy'
STATE.mkdir(exist_ok=True)
PID_FILE = STATE / 'vdl-server.pid'
LOG_FILE = STATE / 'vdl-server.log'
PORT = int(os.environ.get('VDL_PORT', '7431'))
TLS = os.environ.get('VDL_TLS', '').strip().lower() in ('1', 'true', 'yes', 'on')
SCHEME = 'https' if TLS else 'http'
BASE = '%s://127.0.0.1:%d' % (SCHEME, PORT)
PAGES = [
    ('Civil Affairs Portal', '/index.html'),
    ('Frontier Inspection',  '/border.html'),
    ('Interior Inspection',  '/interior.html'),
    ('Chancellery Authority','/admin.html'),
]
BAR = '=' * 68


def port_pids():
    """PIDs actually LISTENING on our designated port (never guess by name)."""
    try:
        r = subprocess.run(['netstat', '-ano', '-p', 'TCP'],
                           capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=8)
        out = r.stdout
    except Exception:
        return []
    pids = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5 or p[0].upper() not in ('TCP', 'TCPV6'):
            continue
        if p[3].upper() != 'LISTENING':
            continue
        if p[1].rsplit(':', 1)[-1] != str(PORT):
            continue
        try:
            pids.add(int(p[4]))
        except ValueError:
            pass
    return sorted(pids)


def recorded_pid():
    try:
        return int(PID_FILE.read_text(encoding='utf-8').strip())
    except Exception:
        return None


def pid_alive(pid):
    try:
        r = subprocess.run(['tasklist', '/FI', 'PID eq %d' % pid, '/NH'],
                           capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=8)
        return str(pid) in r.stdout
    except Exception:
        return False


def http_ok():
    try:
        # A locally generated certificate is not in any trust store; only
        # skip verification for our own loopback probe, never for clients.
        ctx = None
        if TLS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(BASE + '/index.html', timeout=1.2,
                                    context=ctx) as r:
            return r.status == 200
    except Exception:
        return False


def urls():
    return '\n'.join('    %-24s %s%s' % (name, BASE, path) for name, path in PAGES)


def status():
    pids = port_pids()
    rp = recorded_pid()
    print('  指定端口        : %d (VDL_PORT 可覆盖)' % PORT)
    print('  端口监听进程    : %s' % (', '.join(map(str, pids)) if pids else '无'))
    print('  记录的服务器 PID: %s%s' % (rp if rp else '无',
          '  (进程仍在)' if rp and pid_alive(rp) else '  (已退出)' if rp else ''))
    print('  HTTP 探测       : %s' % ('200 OK · 服务可用' if http_ok() else '不可达'))
    print('  四个终端地址    :')
    print(urls())


def start():
    pids = port_pids()
    if pids:
        print('  端口 %d 已被占用：PID %s' % (PORT, ', '.join(map(str, pids))))
        if http_ok():
            print('  政务服务似乎已在运行，无需重复启动。')
        else:
            print('  该进程不是可用的政务服务，请先选 [2] 停止。')
        return False
    try:
        log = LOG_FILE.open('a', encoding='utf-8')
        log.write('\n--- start %s ---\n' % time.strftime('%Y-%m-%d %H:%M:%S'))
        log.flush()
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        breakaway = getattr(subprocess, 'CREATE_BREAKAWAY_FROM_JOB', 0)
        argv = [sys.executable, str(ROOT / 'serve.py')]
        try:
            # Detach from the launcher's job so the server survives even if
            # the console that started it is closed.
            p = subprocess.Popen(argv, cwd=str(ROOT), stdout=log,
                                 stderr=subprocess.STDOUT,
                                 creationflags=flags | breakaway)
        except OSError:
            p = subprocess.Popen(argv, cwd=str(ROOT), stdout=log,
                                 stderr=subprocess.STDOUT, creationflags=flags)
        log.close()
        PID_FILE.write_text(str(p.pid), encoding='utf-8')
    except Exception as e:
        print('  启动失败：%s' % e)
        return False
    for _ in range(24):
        if http_ok():
            break
        time.sleep(0.25)
    if http_ok():
        print('  ✓ 政务服务已启动 · PID %d · 端口 %d（后台无窗口运行）' % (p.pid, PORT))
        print(urls())
        return True
    print('  ! 进程已拉起但 HTTP 尚未就绪，请选 [6] 查看日志。')
    return False


def stop(confirm=True):
    pids = set(port_pids())
    rp = recorded_pid()
    if rp and pid_alive(rp):
        pids.add(rp)
    if not pids:
        print('  当前没有运行中的政务服务。')
        try:
            PID_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        return True
    print('  将终止以下进程（仅限端口 %d）：PID %s' %
          (PORT, ', '.join(map(str, sorted(pids)))))
    if confirm:
        try:
            ans = input('  确认终止？[y/N] ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ''
        if ans not in ('y', 'yes'):
            print('  已取消。')
            return False
    for pid in sorted(pids):
        r = subprocess.run(['taskkill', '/F', '/PID', str(pid)],
                           capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
        print('  PID %-7d %s' % (pid, '已终止' if r.returncode == 0 else '未能终止（可能已退出）'))
    try:
        PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    time.sleep(0.5)
    left = port_pids()
    print('  端口状态：%s' % ('仍被占用 %s' % left if left else '已释放'))
    return not left


def restart():
    stop(confirm=False)
    time.sleep(0.4)
    return start()


def open_pages():
    if not http_ok():
        print('  服务尚未就绪，请先选 [1] 启动。')
        return
    for name, path in PAGES:
        webbrowser.open_new_tab(BASE + path)
    print('  已在默认浏览器打开四个终端标签页。')


def view_log():
    if not LOG_FILE.exists():
        print('  暂无日志（服务尚未通过本控制台启动过）。')
        return
    lines = LOG_FILE.read_text(encoding='utf-8', errors='replace').splitlines()
    if not lines:
        print('  日志为空。')
        return
    print('  --- 最后 20 行 · %s ---' % LOG_FILE)
    for ln in lines[-20:]:
        print('  ' + ln)


MENU = '''
%s
  GRAND DUCHY OF VIDLAND  ·  政务系统快捷控制台
  端口 %d  |  四端必须同源访问  |  仅操作本端口进程
%s
   [1] 启动服务器          [2] 停止服务器（杀死进程）
   [3] 重启服务器          [4] 查看状态 / 端口占用
   [5] 浏览器打开四个终端   [6] 查看服务器日志
   [0] 退出控制台
%s''' % (BAR, PORT, BAR, BAR)


def dispatch(choice, interactive=True):
    if choice == '1':
        start()
    elif choice == '2':
        stop(confirm=interactive)
    elif choice == '3':
        restart()
    elif choice == '4':
        status()
    elif choice == '5':
        open_pages()
    elif choice == '6':
        view_log()
    elif choice == '0':
        return False
    else:
        print('  无效选择，请输入 0–6。')
    return True


def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        alias = {'start': '1', 'stop': '2', 'restart': '3',
                 'status': '4', 'open': '5', 'log': '6'}
        if cmd not in alias:
            print('用法: python quickstart.py [start|stop|restart|status|open|log]')
            return 1
        dispatch(alias[cmd], interactive=False)
        return 0
    print(MENU)
    while True:
        try:
            choice = input('\n  请选择 > ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not dispatch(choice):
            break
        try:
            input('\n  按回车返回菜单…')
        except (EOFError, KeyboardInterrupt):
            print()
            break
        print(MENU)
    print('\n  控制台已退出。服务若仍在后台运行，可用 [2] 或 '
          '"python quickstart.py stop" 停止。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
