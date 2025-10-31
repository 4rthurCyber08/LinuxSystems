Manually Create a Honeypot Server using Python

1. Create a python file for the honeypot operation.
~~~
!@NetOps
sudo nano /usr/local/bin/tcp-6969-honeypot.py
~~~

Then paste the following contents to the nano shell.

~~~
#!/usr/bin/env python3
import asyncio
import datetime
import os
import argparse
import binascii
import pathlib

### LOG FILE LOCATION
BASE_LOG = '/var/log/tcp-6969-honeypot'
os.makedirs(BASE_LOG, exist_ok=True)


### CONVERT RAW BYTES TO HUMAN READABLE DATA
def hexdump(data: bytes) -> str:

  ### CONVERT RAW BYTES TO HEX STRINGS
  hexs: binascii.hexlify(data).decode('ascii')
  
  ### LOOP 32 CHAR CHUNKS TO BE A HUMAN READABLE DATA
  lines = []
  for i in range(0, len(hexs), 32):
    chunk = hexs[i:i+32]
    b = bytes.fromhex(chunk)
    printable = ''.join((chr(x) if 32 <= x < 127 else '.') for x in b)
    lines.append(f'{i//2:08x} {chunk} {printable}')
    return '\n'.join(lines)


### LOG INFORMATION ABOUT THE ATTACKER
async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  
  ### IDENTIFY ATTACKER IP
  peer = writer.get_extra_info('peername')
  if peer is None:
    peer = ('unknown', 0)
  ip, port = peer[0], peer[1]
  
  
  ### SESSION LOGS - Year-Month-Day Hour-Minutes-Seconds
  start = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
  sess_name = f"{start}_{ip.replace(':','_')}_{port}"
  sess_dir = pathlib.Path(BASE_LOG) / sess_name
  sess_dir.mkdir(parents=True, exist_ok=True)
  meta_file = sess_dir / "meta.txt"
  
  ### WRITE SESSION LOGS
  with meta_file.open("w") as mf:
    mf.write(f"start: {start}\npeer: {ip}:{port}\n")
  print(f"[+] connection from {ip}:{port} -> {sess_dir}")


  ### SEND MESSAGE TO THE ATTACKER
  try:
    writer.write(b'Welcome to Rivan, you Hacker!!! \r\n')
    await writer.drain()
  except Exception:
    pass


  ### DUMP RAW AND HEX DATA
  raw_file = sess_dir / "raw.bin"
  hexd_file = sess_dir / "hexdump.txt"
  try:
    with raw_file.open("ab") as rb, hexd_file.open("a") as hf:
      while True:
        data = await asyncio.wait_for(reader.read(4096), timeout=300.0)
        if not data:
          break
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        rb.write(data)
        hf.write(f"\n-- {ts} --\n")
        hf.write(hexdump(data) + "\n")
        
        ### RECORD READABLE COPY
        printable = ''.join((chr(x) if 32 <= x < 127 else '.') for x in data)
        (sess_dir / "printable.log").open("a").write(f"{ts} {printable}\n")
        
        ### SEND TARPITTED RESPONSE
        try:
          writer.write(b"OK\r\n")
          await writer.drain()
        except Exception:
          break
  except asyncio.TimeoutError:
    print(f"[-] connection timed out {ip}:{port}")
  except Exception as e:
    print(f"[-] session error {e}")
  finally:
    try:
      writer.close()
      await writer.wait_closed()
    except Exception:
      pass
    end = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    with meta_file.open("a") as mf:
      mf.write(f"end: {end}\n")
    print(f"[+] closed {ip}:{port} -> {sess_dir}")


  ### TCP HANDLER
  async def main(host, port):
    server = await asyncio.start_server(handle, host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Listening on {addrs}")
    async with server:
      await server.serve_forever()
      
  ### CLI ENTRYPOINT
  if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=6969)
    args = parser.parse_args()
    try:
      asyncio.run(main(args.host, args.port))
    except KeyboardInterrupt:
      pass
~~~

> [!NOTE]
> Imports
> - asyncio: event loop + async IO (handles many connections efficiently).
> - datetime: timestamps.
> - os, pathlib: filesystem operations.
> - argparse: parse CLI arguments (--host, --port).
> - binascii: binary ⇄ hex conversion.


2. Create the directory for the log files.

!@NetOps
sudo mkdir /var/log/tcp-6969-honeypot


Make the file excecutable

!@NetOps
sudo chmod +x /usr/local/bin/tcp-6969-honeypot.py


3. Prevent the honeypot server from being conpronised by assigning a nologin account to it.

!@NetOps
sudo useradd -r -s /sbin/nologin honeypot69 || true
sudo chown -R honeypot69:honeypot69 /var/log/tcp-6969-honeypot
sudo chown -R honeypot69:honeypot69 /usr/local/bin/tcp-6969-honeypot.py 

4. Create a Systemd Service unit file

!@NetOps
nano /etc/systemd/system/tcp-6969-honeypot.service

Then paste the following

~~~
[Unit]
Description=A TCP Honeypot for port 6969
After=network.target

[Service]
User=honeypot69
Group=honeypot69
ExecStart=/usr/local/bin/tcp-6969-honeypot.py --host 0.0.0.0 --port 6969
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
ProtectSystem=full
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateNetwork=no
ReadOnlyPaths=/usr
AmbientCapabilities=
SystemCallFilter=~@clock @cpu-emulation

[Install]
WantedBy=multi-user.target
~~~


5. Then start the service

!@NetOps
chmod 755 tcp-6969-honeypot.service 
sudo systemctl daemon-reload
sudo systemctl start tcp-6969-honeypot.service
sudo systemctl status tcp-6969-honeypot.service --no-pager






















### Step 1 - Create a python script to log info
~~~
!@NetOps
sudo tee /usr/local/bin/tcp-honeypot.py > /dev/null <<'PY'
~~~

<br>

~~~
#!/usr/bin/env python3
"""
Simple TCP honeypot:
 - listens on given host:port
 - logs connections (timestamp, src ip:port)
 - dumps raw bytes to per-session files (hexdump + printable)
 - safe for use as a non-root service (binds high ports by default)
"""
import asyncio
import datetime
import os
import argparse
import binascii
import pathlib

BASE_LOG = "/var/log/tcp-honeypot"
os.makedirs(BASE_LOG, exist_ok=True)

def hexdump(data: bytes) -> str:
    hexs = binascii.hexlify(data).decode('ascii')
    lines = []
    for i in range(0, len(hexs), 32):
        chunk = hexs[i:i+32]
        b = bytes.fromhex(chunk)
        printable = ''.join((chr(x) if 32 <= x < 127 else '.') for x in b)
        lines.append(f"{i//2:08x}  {chunk}  {printable}")
    return "\n".join(lines)

async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    if peer is None:
        peer = ("unknown",0)
    ip, port = peer[0], peer[1]
    start = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    sess_name = f"{start}_{ip.replace(':','_')}_{port}"
    sess_dir = pathlib.Path(BASE_LOG) / sess_name
    sess_dir.mkdir(parents=True, exist_ok=True)
    meta_file = sess_dir / "meta.txt"
    with meta_file.open("w") as mf:
        mf.write(f"start: {start}\npeer: {ip}:{port}\n")
    print(f"[+] connection from {ip}:{port} -> {sess_dir}")

    # optional initial bait (comment out if you don't want data sent)
    try:
        writer.write(b"Welcome\r\n")
        await writer.drain()
    except Exception:
        pass

    raw_file = sess_dir / "raw.bin"
    hexd_file = sess_dir / "hexdump.txt"
    try:
        with raw_file.open("ab") as rb, hexd_file.open("a") as hf:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=300.0)
                if not data:
                    break
                ts = datetime.datetime.utcnow().isoformat() + "Z"
                rb.write(data)
                hf.write(f"\n-- {ts} --\n")
                hf.write(hexdump(data) + "\n")
                # record printable copy
                printable = ''.join((chr(x) if 32 <= x < 127 else '.') for x in data)
                (sess_dir / "printable.log").open("a").write(f"{ts} {printable}\n")
                # optional: send tarpitted response (slow)
                try:
                    writer.write(b"OK\r\n")
                    await writer.drain()
                except Exception:
                    break
    except asyncio.TimeoutError:
        print(f"[-] connection timed out {ip}:{port}")
    except Exception as e:
        print(f"[-] session error {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        end = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        with meta_file.open("a") as mf:
            mf.write(f"end: {end}\n")
        print(f"[+] closed {ip}:{port} -> {sess_dir}")

async def main(host, port):
    server = await asyncio.start_server(handle, host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Listening on {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()
    try:
        asyncio.run(main(args.host, args.port))
    except KeyboardInterrupt:
        pass
PY
~~~

<br>

~~~
!@NetOps
mkdir /var/log/tcp-honeypot
~~~

<br>

~~~
!@NetOps
sudo chmod +x /usr/local/bin/tcp-honeypot.py
~~~

<br>

### Step 2 - Create a Systemd service entry
~~~
!@NetOps
sudo useradd -r -s /sbin/nologin honeypot || true
sudo chown -R honeypot:honeypot /var/log/tcp-honeypot
~~~

<br>

~~~
!@NetOps
sudo tee /etc/systemd/system/tcp-honeypot.service > /dev/null <<'UNIT'
~~~

<br>

~~~
[Unit]
Description=Simple TCP Honeypot
After=network.target

[Service]
User=honeypot
Group=honeypot
ExecStart=/usr/local/bin/tcp-honeypot.py --host 0.0.0.0 --port 2222
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
ProtectSystem=full
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateNetwork=no
ReadOnlyPaths=/usr
AmbientCapabilities=
SystemCallFilter=~@clock @cpu-emulation

[Install]
WantedBy=multi-user.target
UNIT
~~~

<br>

~~~
!@NetOps
sudo systemctl daemon-reload
sudo systemctl enable tcp-honeypot.service
sudo systemctl status tcp-honeypot.service --no-pager
~~~





############
V2 - No Logs

~~~
!@NetOps
sudo tee /usr/local/bin/simple-hello-honeypot.py > /dev/null <<'PY'
~~~

<br>

~~~
!@NetOps
#!/usr/bin/env python3
# Minimal TCP "honeypot" that sends a Hello message and closes.
import socket
import sys

HOST = "208.8.8.171"
PORT = 8787  # non-privileged by default

if len(sys.argv) > 1:
    try:
        PORT = int(sys.argv[1])
    except ValueError:
        pass

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        with conn:
            print("Connection from", addr)
            try:
                conn.sendall(b"Hello\r\n")
            except Exception:
                pass
PY
~~~

<br>

~~~
sudo chmod +x /usr/local/bin/simple-hello-honeypot.py
~~~

<br>

### TEST
#sudo /usr/local/bin/simple-hello-honeypot.py 2222
#sudo nohup /usr/local/bin/simple-hello-honeypot.py 2222 &>/var/log/simple-hello-honeypot.log &

<br>

~~~
!@NetOps
nano /etc/systemd/system/simple-hello-honeypot.service
~~~

<br>

~~~
[Unit]
Description=Simple Hello Honeypot
After=network.target

[Service]
ExecStart=/usr/local/bin/simple-hello-honeypot.py 8787
User=nobody
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
~~~

<br>

~~~
!@NetOps
sudo systemctl daemon-reload
sudo systemctl start simple-hello-honeypot.service
~~~
