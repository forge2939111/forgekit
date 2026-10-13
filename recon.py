#!/usr/bin/env python3
import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import re
import socket
import ssl
import sys
import time

# ------------------------------------------------------------------------
# İzin / yasal onay kapısı
# ------------------------------------------------------------------------
LEGAL_NOTICE = """\
================================================================================
  UYARI: Bu araç yalnızca aşağıdaki durumlarda kullanılabilir:
    1) Kendi sahip olduğunuz / kurduğunuz bir lab ortamı,
    2) CTF veya eğitim platformu (HackTheBox, TryHackMe vb.) hedefi,
    3) Yazılı, imzalı izniniz olan bir pentest/güvenlik testi kapsamı.
  İzniniz olmayan bir sisteme karşı tarama yapmak suç oluşturabilir
  (TCK 243-244, KVKK ve ilgili diğer mevzuat).

  FOR LEGAL USE ONLY. I don't consent to this tool being used for any
  illegal purpose. The author is not responsible for misuse.
================================================================================
"""

PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128",
)]


def looks_private_or_local(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if any(ip in net for net in PRIVATE_NETS):
            return True
    return False


def confirm_authorization(target: str, assume_yes: bool) -> None:
    print(LEGAL_NOTICE)
    if assume_yes:
        print(f"[*] --yes-i-am-authorized bayrağı verildi, '{target}' için onay alınmış kabul ediliyor.\n")
        return
    private = looks_private_or_local(target)
    hint = " (özel/yerel bir adrese benziyor)" if private else " — bu genel bir adrese benziyor, dikkatli olun"
    print(f"Hedef: {target}{hint}")
    ans = input("Bu hedefte tarama yapmak için yetkiniz olduğunu onaylıyor musunuz? (devam etmek için büyük harfle EVET yazın): ")
    if ans.strip() != "EVET":
        print("Onaylanmadı, çıkılıyor.")
        sys.exit(1)
    print()


# ------------------------------------------------------------------------
# Tarama
# ------------------------------------------------------------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080, 8443]


def parse_ports(spec: str):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def tcp_connect(host: str, port: int, timeout: float):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return s is not None
    except OSError:
        return False


def scan_ports(host: str, ports, timeout: float, workers: int, progress=True):
    open_ports = []
    total = len(ports)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(tcp_connect, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if progress and (done % 50 == 0 or done == total):
                print(f"\r[*] Taranan port: {done}/{total}", end="", flush=True)
            if fut.result():
                open_ports.append(futs[fut])
    if progress:
        print()
    return sorted(open_ports)


# ------------------------------------------------------------------------
# Servis / banner tespiti
# ------------------------------------------------------------------------
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 8090}
TLS_PORTS = {443, 8443, 993, 995}


def _recv_all(sock, cap=8192):
    data = b""
    try:
        while len(data) < cap:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def _open(host, port, timeout, tls):
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    else:
        sock = raw_sock
    sock.settimeout(timeout)
    return sock


def grab_banner(host: str, port: int, timeout: float):
    """Porttan servis banner'ı okumaya çalışır. Önce pasif banner (ör. FTP/SSH/SMTP
    bağlantı açılır açılmaz kendini tanıtır), sonuç boşsa HTTP HEAD isteğiyle dener."""
    use_tls = port in TLS_PORTS
    data = b""
    try:
        sock = _open(host, port, timeout, use_tls)
        try:
            data = _recv_all(sock)
            if not data and port in (25, 587):
                sock.sendall(b"EHLO recon\r\n")
                data = _recv_all(sock)
        finally:
            sock.close()
    except OSError:
        pass

    if not data:
        try:
            sock = _open(host, port, timeout, use_tls)
            try:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                data = _recv_all(sock)
            finally:
                sock.close()
        except OSError:
            pass

    return data.decode(errors="replace").strip()


# software -> (regex, çıkan grup = sürüm metni)
VERSION_PATTERNS = [
    ("OpenSSH", re.compile(r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)")),
    ("Apache httpd", re.compile(r"Apache/([\d.]+)")),
    ("nginx", re.compile(r"nginx/([\d.]+)")),
    ("Microsoft IIS", re.compile(r"Microsoft-IIS/([\d.]+)")),
    ("vsftpd", re.compile(r"vsftpd ([\d.]+)")),
    ("ProFTPD", re.compile(r"ProFTPD ([\d.]+)")),
    ("Pure-FTPd", re.compile(r"Pure-?FTPd", re.I)),
    ("MySQL", re.compile(r"mysql_native_password|(\d+\.\d+\.\d+)-MariaDB|(\d+\.\d+\.\d+)-log")),
    ("PostgreSQL", re.compile(r"PostgreSQL")),
    ("Exim", re.compile(r"Exim ([\d.]+)")),
    ("Postfix", re.compile(r"Postfix")),
    ("Samba", re.compile(r"Samba ([\d.]+)")),
    ("Dropbear SSH", re.compile(r"SSH-[\d.]+-dropbear[_-]?([\w.]*)")),
    ("lighttpd", re.compile(r"lighttpd/([\d.]+)")),
    ("PHP", re.compile(r"PHP/([\d.]+)")),
]

PORT_SERVICE_GUESS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds (smb)", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-proxy",
    8443: "https-alt",
}


def identify_service(host, port, timeout):
    banner = grab_banner(host, port, timeout)
    product, version = None, None
    for name, pat in VERSION_PATTERNS:
        m = pat.search(banner)
        if m:
            product = name
            groups = [g for g in (m.groups() or []) if g]
            version = groups[0] if groups else None
            break
    if not product:
        m = re.search(r"Server:\s*([^\r\n]+)", banner, re.I)
        if m:
            product = m.group(1).strip()
    guess = PORT_SERVICE_GUESS.get(port, "bilinmiyor")
    first_line = banner.splitlines()[0].strip() if banner else ""
    first_line = "".join(c if c.isprintable() else "." for c in first_line)
    return {
        "port": port,
        "guessed_service": guess,
        "product": product,
        "version": version,
        "banner_excerpt": first_line[:120],
    }


# ------------------------------------------------------------------------
# Rapor
# ------------------------------------------------------------------------
def build_report(target, started, finished, services, md_path, json_path=None):
    lines = []
    lines.append(f"# Keşif Raporu — {target}")
    lines.append("")
    lines.append(f"- Başlangıç: {started.isoformat(timespec='seconds')}")
    lines.append(f"- Bitiş: {finished.isoformat(timespec='seconds')}")
    lines.append(f"- Süre: {(finished - started).total_seconds():.1f} sn")
    lines.append(f"- Açık port sayısı: {len(services)}")
    lines.append("")
    lines.append("> Bu rapor eğitim/CTF amaçlıdır; hiçbir sömürü (exploit) adımı içermez.")
    lines.append("")
    lines.append("## Bulunan Servisler")
    lines.append("")
    lines.append("| Port | Servis (tahmin) | Ürün | Sürüm | Banner özeti |")
    lines.append("|---|---|---|---|---|")
    for s in services:
        lines.append(f"| {s['port']} | {s['guessed_service']} | {s['product'] or '-'} | {s['version'] or '-'} | `{s['banner_excerpt'] or '-'}` |")
    lines.append("")
    lines.append("## Genel Öneriler")
    lines.append("")
    lines.append("- Kullanılmayan servisleri/portları kapatın.")
    lines.append("- Tüm servisleri güncel, desteklenen sürümlerde tutun.")
    lines.append("- Dışarıya açık yönetim arayüzlerini (RDP, VNC, telnet) güçlü kimlik doğrulama ve ağ kısıtlamasıyla koruyun.")
    lines.append("")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "target": target, "started": started.isoformat(), "finished": finished.isoformat(),
                "services": services,
            }, f, ensure_ascii=False, indent=2)


# ------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Eğitim/CTF amaçlı ağ keşif ve bilinen-zafiyet-farkındalık aracı")
    ap.add_argument("target", help="Hedef IP adresi veya host adı")
    ap.add_argument("--ports", default=None, help='Port listesi/aralığı, örn. "1-1000" veya "22,80,443". Verilmezse sık kullanılan portlar taranır.')
    ap.add_argument("--timeout", type=float, default=0.8, help="Bağlantı zaman aşımı (sn), varsayılan 0.8")
    ap.add_argument("--workers", type=int, default=200, help="Eşzamanlı iş parçacığı sayısı, varsayılan 200")
    ap.add_argument("--output", default=None, help="Markdown rapor dosyası yolu (varsayılan: recon-<hedef>-<tarih>.md)")
    ap.add_argument("--json", action="store_true", help="JSON çıktı da üret")
    ap.add_argument("--yes-i-am-authorized", action="store_true",
                     help="Yasal onay sorusunu atla (sadece otomasyon/CI için; bunu kullanmak, izniniz olduğunu kabul ettiğiniz anlamına gelir)")
    args = ap.parse_args()

    confirm_authorization(args.target, args.yes_i_am_authorized)

    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
    print(f"[*] Hedef: {args.target}  |  Port sayısı: {len(ports)}")
    started = datetime.datetime.now()

    open_ports = scan_ports(args.target, ports, args.timeout, args.workers)
    print(f"[*] Açık port bulundu: {len(open_ports)} -> {open_ports}")

    services = []
    for p in open_ports:
        print(f"[*] Servis tespiti: port {p} ...")
        services.append(identify_service(args.target, p, max(args.timeout, 1.5)))

    finished = datetime.datetime.now()

    safe_target = re.sub(r"[^\w.-]", "_", args.target)
    md_path = args.output or f"recon-{safe_target}-{started.strftime('%Y%m%d-%H%M%S')}.md"
    json_path = md_path.rsplit(".", 1)[0] + ".json" if args.json else None
    build_report(args.target, started, finished, services, md_path, json_path)

    print(f"\n[+] Rapor yazıldı: {md_path}")
    if json_path:
        print(f"[+] JSON çıktı yazıldı: {json_path}")


if __name__ == "__main__":
    main()
