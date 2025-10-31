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
  hexs = binascii.hexlify(data).decode('ascii')
  
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
        with (sess_dir / "printable.log").open("a") as pf:
          pf.write(f"{ts} {printable}\n")
        
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
sudo systemctl daemon-reload
sudo systemctl start tcp-6969-honeypot.service
sudo systemctl status tcp-6969-honeypot.service --no-pager









6. OPTIONAL
If binding to ports below 1024 use the following systemd setup
~~~
NoNewPrivileges=No
AmbientCapabilities=CAP_NET_BIND_SERVICE
~~~
