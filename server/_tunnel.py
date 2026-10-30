#!/usr/bin/env python3
"""临时用 paramiko 建本地端口转发 (localhost:18443 -> <服务器地址>:8443)。"""
import os, socket, sys, threading, time, select

import paramiko

from _deploy_secrets import HOST, USER, validate
from _ssh import connect

def forward(local_port, remote_host, remote_port, transport):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", local_port))
    srv.listen(5)
    print(f"listening {local_port} -> {remote_host}:{remote_port}", flush=True)
    while True:
        try:
            cli, addr = srv.accept()
        except OSError:
            return
        def handle():
            try:
                chan = transport.open_channel("direct-tcpip",
                                              (remote_host, remote_port), addr)
            except Exception as e:
                print("chan err:", e); cli.close(); return
            if chan is None:
                cli.close(); return
            try:
                while True:
                    r, _, _ = select.select([cli, chan], [], [], 1.0)
                    if cli in r:
                        d = cli.recv(4096)
                        if not d: break
                        chan.sendall(d)
                    if chan in r:
                        d = chan.recv(4096)
                        if not d: break
                        cli.sendall(d)
            finally:
                chan.close(); cli.close()
        threading.Thread(target=handle, daemon=True).start()

def main():
    validate()
    ssh = connect(HOST, USER)
    print("ssh connected", flush=True)
    t = ssh.get_transport()
    t.set_keepalive(15)
    forward(18443, "127.0.0.1", 8443, t)

if __name__ == "__main__":
    main()
