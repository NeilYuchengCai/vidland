#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grand Duchy of Vidland · Chancellery Quick Console

Looping menu for the four terminals. Operates ONLY on the process that
listens on the designated port (7431 by default); it never kills an
unrelated Python or browser process.

    python quickstart.py              -> looping menu
    python quickstart.py start        -> one-shot commands
    python quickstart.py stop | restart | status | open | log | lan
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
PORT = int(os.environ.get('VDL_PORT', '7431'))
# PID/log files are per-port. A shared file made "stop" on one VDL_PORT
# kill the recorded PID of a server listening on a different port.
PID_FILE = STATE / ('vdl-server-%d.pid' % PORT)
LOG_FILE = STATE / ('vdl-server-%d.log' % PORT)
LEGACY_PID_FILE = STATE / 'vdl-server.pid'   # written by older releases
LEGACY_LOG_FILE = STATE / 'vdl-server.log'


def tls_on():
    return (os.environ.get('VDL_LAN', '').strip().lower() in ('1', 'true', 'yes', 'on')
            or os.environ.get('VDL_TLS', '').strip().lower() in ('1', 'true', 'yes', 'on'))


MODE_LABEL = {'http': 'HTTP · 本机模式', 'https': 'HTTPS · 局域网模式'}


def _probe(scheme):
    """Probe one scheme. LAN certs are self-signed, so verification is
    skipped for this loopback-only check (never for real clients)."""
    try:
        ctx = None
        if scheme == 'https':
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(
                '%s://127.0.0.1:%d/index.html' % (scheme, PORT),
                timeout=0.8, context=ctx) as r:
            return r.status == 200
    except Exception:
        return False


def probe_scheme():
    """The scheme the RUNNING service actually speaks, or None.

    A server started earlier with [7] keeps serving HTTPS even after a new
    console is opened with no VDL_LAN set. Guessing from this process's own
    environment made a healthy server look dead; probe both schemes instead.
    """
    preferred = 'https' if tls_on() else 'http'
    for scheme in (preferred, 'https' if preferred == 'http' else 'http'):
        if _probe(scheme):
            return scheme
    return None


def base_url():
    live = probe_scheme()
    return '%s://127.0.0.1:%d' % (live or ('https' if tls_on() else 'http'), PORT)
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
    for f in (PID_FILE, LEGACY_PID_FILE if PORT == 7431 else PID_FILE):
        try:
            return int(f.read_text(encoding='utf-8').strip())
        except Exception:
            pass
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
    return probe_scheme() is not None


def urls():
    base = base_url()
    return '\n'.join('    %-24s %s%s' % (name, base, path) for name, path in PAGES)


def status():
    pids = port_pids()
    rp = recorded_pid()
    live = probe_scheme()
    print('  指定端口        : %d (VDL_PORT 可覆盖)' % PORT)
    print('  端口监听进程    : %s' % (', '.join(map(str, pids)) if pids else '无'))
    print('  记录的服务器 PID: %s%s' % (rp if rp else '无',
          '  (进程仍在)' if rp and pid_alive(rp) else '  (已退出)' if rp else ''))
    print('  运行模式        : %s' % (MODE_LABEL[live] if live else '未运行'))
    print('  服务探测        : %s' % ('200 OK · 服务可用' if live else '不可达'))
    print('  四个终端地址    :')
    print(urls())
    if live == 'https':
        print('  提示：当前是局域网模式，请按 HTTPS 地址访问；'
              '要回到本机 HTTP 模式可先选 [2] 停止，再选 [1] 启动。')


def start():
    pids = port_pids()
    if pids:
        live = probe_scheme()
        wanted = 'https' if tls_on() else 'http'
        print('  端口 %d 已被占用：PID %s' % (PORT, ', '.join(map(str, pids))))
        if live:
            print('  政务服务已在运行（%s），无需重复启动。' % MODE_LABEL[live])
            print('  正确地址：%s/index.html' % base_url())
            if live != wanted:
                print('  注意：本次命令想要的是 %s；'
                      '如需切换，请先选 [2] 停止，再重新启动。' % MODE_LABEL[wanted])
            print(urls())
            return True
        print('  端口被占用但服务无响应（可能是残留进程或非本项目服务），'
              '请先选 [2] 停止后再启动。')
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
    expected = 'https' if tls_on() else 'http'
    for _ in range(24):
        if _probe(expected):
            break
        time.sleep(0.25)
    if _probe(expected):
        print('  ✓ 政务服务已启动 · PID %d · 端口 %d（后台无窗口运行）' % (p.pid, PORT))
        print(urls())
        return True
    print('  ! 进程已拉起但 HTTP 尚未就绪，请选 [6] 查看日志。')
    return False


def stop(confirm=True):
    # Only ever touch PIDs that are actually LISTENING on THIS port. The
    # recorded PID is a hint for display, never a kill target on its own.
    pids = set(port_pids())
    rp = recorded_pid()
    if not pids:
        print('  当前没有运行中的政务服务。')
        for f in (PID_FILE, LEGACY_PID_FILE if PORT == 7431 else PID_FILE):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        return True
    if rp and rp not in pids:
        print('  提示：记录的 PID %d 未在本端口监听，已忽略（不终止）。' % rp)
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
    for f in (PID_FILE, LEGACY_PID_FILE if PORT == 7431 else PID_FILE):
        try:
            f.unlink(missing_ok=True)
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
    live = probe_scheme()
    if not live:
        print('  服务尚未就绪，请先选 [1] 启动。')
        return
    base = '%s://127.0.0.1:%d' % (live, PORT)
    for name, path in PAGES:
        webbrowser.open_new_tab(base + path)
    print('  已在默认浏览器打开四个终端标签页。')


def view_log():
    log = LOG_FILE
    if not log.exists() and PORT == 7431 and LEGACY_LOG_FILE.exists():
        log = LEGACY_LOG_FILE
    if not log.exists():
        print('  暂无日志（服务尚未通过本控制台启动过）。')
        return
    lines = log.read_text(encoding='utf-8', errors='replace').splitlines()
    if not lines:
        print('  日志为空。')
        return
    print('  --- 最后 20 行 · %s ---' % log)
    for ln in lines[-20:]:
        print('  ' + ln)


def lan_start():
    """Start LAN mode: HTTPS on 0.0.0.0, with a local CA for phone trust."""
    import subprocess as _sp
    cert = ROOT / 'vidland-data' / 'lan-cert.pem'
    # Idempotent: creates the CA on first run, auto-renews the server cert
    # before expiry or when the LAN IP changes, and keeps the CA so phones
    # never need to reinstall anything.
    r = _sp.run([sys.executable, str(ROOT / 'make_cert.py'), '--quiet'],
                cwd=str(ROOT), capture_output=True, text=True,
                encoding='utf-8', errors='replace')
    if r.returncode != 0 or not cert.is_file():
        print('  证书生成失败，局域网模式需要 TLS 证书。')
        # Surface BOTH streams: some failures are reported on stdout.
        detail = (r.stderr or '').strip() or (r.stdout or '').strip()
        if detail:
            print('  原因：')
            for line in detail.splitlines():
                print('  ' + line)
        else:
            print('  原因：make_cert.py 退出码 %d，未给出更多信息。' % r.returncode)
            print('  可手动运行 python make_cert.py 查看详细输出。')
        return False
    os.environ['VDL_LAN'] = '1'
    os.environ['VDL_TLS'] = '1'
    ok = start()
    if ok:
        try:
            import socket as _s
            s = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            s.connect(('223.5.5.5', 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = '192.168.x.x'
        base = 'https://%s:%d' % (ip, PORT)
        ca_port = int(os.environ.get('VDL_CA_PORT', str(PORT + 1)))
        enrol = 'http://%s:%d/' % (ip, ca_port)
        # Keep the printed terminal URLs consistent with the address phones
        # must actually use; urls() above targets loopback for local checks.
        print('\n  局域网模式已启用（HTTPS · 0.0.0.0:%d）' % PORT)
        print('  【手机第一步】在 Safari 地址栏手动完整输入这个纯 HTTP 地址：')
        print('      %s' % enrol)
        print('    iPhone 点「下载配置描述文件」→ 设置里安装 → 证书信任设置开启完全信任。')
        print('    Android 点「下载根证书 (.crt)」→ 设置里作为 CA 证书安装。')
        print('    这个页面只下发根证书，不含存档和密钥；绕过「未信任证书打不开 HTTPS」的死循环。')
        print('  【第二步】装好后改用 HTTPS 访问终端（必须带 https://）：')
        for _name, _path in PAGES:
            _note = '  [仅本机]' if _path == '/admin.html' else ''
            print('    %-24s %s%s%s' % (_name, base, _path, _note))
        print('  管理端 admin.html 仅本机可访问（保护私钥）。')
        print('  若手机连不上，请放行 Windows 防火墙 TCP %d 入站。' % PORT)
    return ok


MENU = '''
%s
  GRAND DUCHY OF VIDLAND  ·  政务系统快捷控制台
  端口 %d  |  四端必须同源访问  |  仅操作本端口进程
%s
   [1] 启动服务器          [2] 停止服务器（杀死进程）
   [3] 重启服务器          [4] 查看状态 / 端口占用
   [5] 浏览器打开四个终端   [6] 查看服务器日志
   [7] 局域网模式（手机）   [0] 退出控制台
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
    elif choice == '7':
        lan_start()
    elif choice == '0':
        return False
    else:
        print('  无效选择，请输入 0–7。')
    return True


def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        alias = {'start': '1', 'stop': '2', 'restart': '3',
                 'status': '4', 'open': '5', 'log': '6', 'lan': '7'}
        if cmd not in alias:
            print('用法: python quickstart.py [start|stop|restart|status|open|log|lan]')
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
