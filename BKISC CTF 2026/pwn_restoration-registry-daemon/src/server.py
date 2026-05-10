#!/usr/bin/env python3
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get("RRD_HOST", "0.0.0.0")
PORT = int(os.environ.get("RRD_PORT", "5000"))
SESSION_TIMEOUT = int(os.environ.get("RRD_SESSION_TIMEOUT", "180"))
BACKLOG = int(os.environ.get("RRD_BACKLOG", "64"))
IPC_FD_ENV = "RRD_IPC_FD"
SENSITIVE_ENV_KEYS = ("GZCTF_FLAG",)

session_lock = threading.Lock()
session_counter = 0


def next_session_id():
    global session_counter
    with session_lock:
        session_counter += 1
        return session_counter


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def resolve_binary_path(binary_name, override_name):
    override = os.environ.get(override_name)
    if override:
        return override

    candidates = (
        os.path.join(ROOT, "build", "src", binary_name),
        os.path.join(ROOT, binary_name),
    )

    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return candidates[0]


REGISTRY_BIN = resolve_binary_path("registryd", "RRD_CORE_PATH")
DIRECTORY_BIN = resolve_binary_path("directoryd", "DIRECTORY_BIN_PATH")


def sanitized_child_env():
    env = os.environ.copy()

    for key in SENSITIVE_ENV_KEYS:
        env.pop(key, None)

    return env


def spawn_pair():
    reg_end, dir_end = socket.socketpair()

    try:
        reg_end.set_inheritable(True)
        dir_end.set_inheritable(True)

        dir_env = sanitized_child_env()
        dir_env[IPC_FD_ENV] = str(dir_end.fileno())
        dir_proc = subprocess.Popen(
            [DIRECTORY_BIN],
            cwd=ROOT,
            env=dir_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(dir_end.fileno(),),
            close_fds=True,
            start_new_session=True,
        )

        reg_env = sanitized_child_env()
        reg_env[IPC_FD_ENV] = str(reg_end.fileno())
        reg_proc = subprocess.Popen(
            [REGISTRY_BIN],
            cwd=ROOT,
            env=reg_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            pass_fds=(reg_end.fileno(),),
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
    finally:
        reg_end.close()
        dir_end.close()

    return reg_proc, dir_proc


def kill_process_tree(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    time.sleep(0.1)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def proxy_session(conn, addr, session_id):
    peer = f"{addr[0]}:{addr[1]}"
    reg_proc = None
    dir_proc = None
    sel = selectors.DefaultSelector()
    last_activity = time.monotonic()

    log(f"[session {session_id}] open {peer}")
    conn.setblocking(False)

    try:
        reg_proc, dir_proc = spawn_pair()
        sel.register(conn, selectors.EVENT_READ, "sock")
        sel.register(reg_proc.stdout, selectors.EVENT_READ, "core")

        while True:
            if dir_proc.poll() is not None:
                break
            if reg_proc.poll() is not None and not sel.get_map().get(reg_proc.stdout.fileno()):
                break

            if time.monotonic() - last_activity > SESSION_TIMEOUT:
                try:
                    conn.sendall(b"\n[server] session timeout\n")
                except OSError:
                    pass
                break

            events = sel.select(timeout=1.0)
            if not events:
                if reg_proc.poll() is not None or dir_proc.poll() is not None:
                    break
                continue

            for key, _ in events:
                if key.data == "sock":
                    try:
                        data = conn.recv(4096)
                    except BlockingIOError:
                        continue
                    except OSError:
                        data = b""

                    if not data:
                        return

                    last_activity = time.monotonic()
                    try:
                        reg_proc.stdin.write(data)
                        reg_proc.stdin.flush()
                    except (BrokenPipeError, OSError):
                        return

                elif key.data == "core":
                    try:
                        data = os.read(reg_proc.stdout.fileno(), 4096)
                    except OSError:
                        data = b""

                    if not data:
                        try:
                            sel.unregister(reg_proc.stdout)
                        except Exception:
                            pass
                        continue

                    last_activity = time.monotonic()
                    try:
                        conn.sendall(data)
                    except OSError:
                        return

    finally:
        try:
            sel.close()
        except Exception:
            pass
        try:
            conn.close()
        except OSError:
            pass
        if reg_proc is not None:
            kill_process_tree(reg_proc)
            if reg_proc.stdin:
                reg_proc.stdin.close()
            if reg_proc.stdout:
                reg_proc.stdout.close()
        if dir_proc is not None:
            kill_process_tree(dir_proc)
        log(f"[session {session_id}] close {peer}")


def serve():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(BACKLOG)
        log(f"[server] listening on {HOST}:{PORT}")

        while True:
            conn, addr = srv.accept()
            session_id = next_session_id()
            thread = threading.Thread(
                target=proxy_session,
                args=(conn, addr, session_id),
                daemon=True,
            )
            thread.start()


if __name__ == "__main__":
    try:
        serve()
    except KeyboardInterrupt:
        log("[server] shutdown")
