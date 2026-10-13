#!/usr/bin/env python3
"""
ForgeKit (menu.py) — recon.py için SET (Social-Engineer Toolkit) tarzı numaralı menü arayüzü.

ÖNEMLİ: Bu, SADECE görünüm/etkileşim biçimidir (banner + numaralı menü).
İçeride çalışan tek şey recon.py'deki teknik keşif/servis-tespiti/bilinen-
zafiyet-eşleştirme mantığıdır. Phishing, kimlik avı, sahte sayfa/mesaj,
kullanıcı kandırma modülü YOKTUR ve eklenmeyecektir.

Çalıştırma:
    python3 menu.py
"""
import datetime
import os
import shutil
import subprocess
import sys
from urllib.parse import urlparse

import recon as r

BANNER = r"""
  ███████╗ ██████╗ ██████╗  ██████╗ ███████╗██╗  ██╗██╗████████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝██║ ██╔╝██║╚══██╔══╝
  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  █████╔╝ ██║   ██║
  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  ██╔═██╗ ██║   ██║
  ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗██║  ██╗██║   ██║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝

        Eğitim / CTF Ağ Keşif ve Zafiyet-Farkındalık Araç Seti
        (sömürü kodu YOK — sadece keşif, tespit, raporlama)
                    made by EFE KUŞCU
"""

DISCLAIMER = """\
Bu araç yalnızca kendi lab ortamınızda, CTF/eğitim platformlarında veya
yazılı izniniz olan bir pentest kapsamında kullanılabilir. İzinsiz
kullanım suç oluşturabilir.

FOR LEGAL USE ONLY. I don't consent to this tool being used for any
illegal purpose. The author is not responsible for misuse.
"""


def pause():
    input("\n[Devam etmek için Enter'a basın] ")


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val if val else default


class Session:
    def __init__(self):
        self.target = None
        self.ports = None
        self.services = None
        self.started = None
        self.finished = None
        self.authorized_targets = set()


def ensure_authorized(sess, target):
    if target in sess.authorized_targets:
        return True
    try:
        r.confirm_authorization(target, assume_yes=False)
    except SystemExit:
        return False
    sess.authorized_targets.add(target)
    return True


def ensure_authorized_url(sess, url):
    """URL alan araçlar için: URL'den host'u çıkarıp aynı onay kapısından geçirir."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname
    if not host:
        print("[!] Geçerli bir URL/host anlaşılamadı.")
        return False
    return ensure_authorized(sess, host)


def run_tool(cmd):
    print(f"\n[*] Çalıştırılıyor: {' '.join(cmd)}\n(Durdurmak için Ctrl+C)\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Durduruldu.")
    except FileNotFoundError:
        print(f"[!] Çalıştırılamadı: {cmd[0]} bulunamadı.")


def menu_scan(sess, port_spec, label):
    target = ask("Hedef IP/host", sess.target)
    if not target:
        print("[!] Hedef boş olamaz.")
        return
    if not ensure_authorized(sess, target):
        return
    ports = r.parse_ports(port_spec) if port_spec else r.COMMON_PORTS
    timeout = float(ask("Zaman aşımı (sn)", "0.8"))
    workers = int(ask("Eşzamanlı iş parçacığı", "200"))

    print(f"\n[*] {label} başlatılıyor -> {target}  ({len(ports)} port)")
    started = datetime.datetime.now()
    open_ports = r.scan_ports(target, ports, timeout, workers)
    print(f"[*] Açık port: {len(open_ports)} -> {open_ports}")

    services = []
    for p in open_ports:
        print(f"[*] Servis tespiti: port {p} ...")
        services.append(r.identify_service(target, p, max(timeout, 1.5)))
    finished = datetime.datetime.now()

    sess.target, sess.ports, sess.services = target, ports, services
    sess.started, sess.finished = started, finished
    print(f"\n[+] Tarama bitti. '{label}' sonuçları menüden görüntülenebilir/raporlanabilir.")
    pause()


def menu_view_results(sess):
    if sess.services is None:
        print("[!] Henüz bir tarama sonucu yok. Önce bir tarama çalıştırın.")
        pause()
        return
    if not sess.services:
        print(f"\nHedef: {sess.target}   Açık port bulunamadı (taranan sık kullanılan/belirtilen portların hiçbiri açık değil).")
        pause()
        return
    print(f"\nHedef: {sess.target}   Açık port: {len(sess.services)}\n")
    print(f"{'PORT':<8}{'ÜRÜN':<20}{'SÜRÜM':<15}BANNER")
    print("-" * 70)
    for s in sess.services:
        print(f"{s['port']:<8}{(s['product'] or '-'):<20}{(s['version'] or '-'):<15}{s['banner_excerpt'][:30]}")

    print("\nBilinen zafiyet eşleşmeleri:")
    any_hit = False
    for s in sess.services:
        for h in r.match_known_vulns(s["product"], s["version"]):
            any_hit = True
            print(f"  [Port {s['port']}] {s['product']} {s['version'] or ''} -> {h['cve']} ({h['severity']})")
            print(f"      {h['desc']}")
    if not any_hit:
        print("  (eşleşme bulunamadı)")
    pause()


def menu_report(sess):
    if sess.services is None:
        print("[!] Önce bir tarama çalıştırın.")
        pause()
        return
    if not sess.services:
        print("[!] Son taramada açık port bulunamadığı için raporlanacak bir servis yok.")
        pause()
        return
    safe_target = __import__("re").sub(r"[^\w.-]", "_", sess.target)
    default_name = f"recon-{safe_target}-{sess.started.strftime('%Y%m%d-%H%M%S')}.md"
    md_path = ask("Rapor dosya adı", default_name)
    want_json = ask("JSON çıktı da üretilsin mi? (e/h)", "h").lower().startswith("e")
    json_path = md_path.rsplit(".", 1)[0] + ".json" if want_json else None
    r.build_report(sess.target, sess.started, sess.finished, sess.services, md_path, json_path)
    print(f"\n[+] Rapor yazıldı: {md_path}")
    if json_path:
        print(f"[+] JSON yazıldı: {json_path}")
    pause()


def menu_vulndb():
    print("\nYerel bilinen-zafiyet referans listesi (sadece bilgilendirme amaçlı):\n")
    for e in r.KNOWN_VULN_DB:
        print(f"- {e['product']:<16} desen={e['version_pattern']:<18} {e['cve']} [{e['severity']}]")
        print(f"    {e['desc']}")
    pause()


COMMON_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/john/password.lst",
]


def find_john():
    return shutil.which("john")


def guess_wordlist():
    for w in COMMON_WORDLISTS:
        if os.path.isfile(w):
            return w
    return None


def menu_john(sess):
    """John the Ripper'ı (sistemde kuruluysa) çağıran sarmalayıcı.
    Burada hiçbir hash/kırma mantığı kendimiz yazmıyoruz; sadece kurulu
    `john` komutunu, kullanıcının kendi (izinli) hash dosyasına karşı
    çalıştırıyor ve çıktısını okunur biçimde gösteriyoruz."""
    john_bin = find_john()
    if not john_bin:
        print("""
[!] 'john' (John the Ripper) bu sistemde kurulu değil veya PATH'te bulunamadı.

Kurmak için:
    Debian/Ubuntu/Kali : sudo apt install john
    Fedora             : sudo dnf install john
    Arch               : sudo pacman -S john

Kurduktan sonra menüden tekrar deneyin.""")
        pause()
        return

    print(f"\n[*] John the Ripper bulundu: {john_bin}")
    hash_file = ask("Hash dosyasının yolu (örn. /home/efe/hashes.txt)")
    if not hash_file or not os.path.isfile(hash_file):
        print("[!] Dosya bulunamadı.")
        pause()
        return

    print(DISCLAIMER)
    ans = input("Bu hash dosyasını kırmaya yetkiniz/izniniz olduğunu onaylıyor musunuz? "
                 "(kendi hash'iniz veya izinli bir CTF/pentest dosyası olmalı) (EVET yazın): ")
    if ans.strip() != "EVET":
        print("Onaylanmadı, çıkılıyor.")
        pause()
        return

    fmt = ask("Hash formatı (biliyorsanız, örn. raw-md5, sha256crypt; bilmiyorsanız boş bırakın)", "")
    mode = ask("Mod: [1] Wordlist  [2] John'un kendi kural tabanlı modu (--single)  [3] Brute-force (--incremental)", "1")

    cmd = [john_bin]
    if fmt:
        cmd.append(f"--format={fmt}")

    if mode == "1":
        wl_default = guess_wordlist() or ""
        wl = ask("Wordlist dosya yolu", wl_default)
        if not wl or not os.path.isfile(wl):
            print("[!] Wordlist bulunamadı. Debian/Ubuntu'da 'sudo apt install wordlists' ile rockyou.txt kurabilirsiniz.")
            pause()
            return
        cmd += [f"--wordlist={wl}", hash_file]
    elif mode == "3":
        cmd += ["--incremental", hash_file]
    else:
        cmd += ["--single", hash_file]

    print(f"\n[*] Çalıştırılıyor: {' '.join(cmd)}\n(Durdurmak için Ctrl+C)\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Durduruldu.")
    except FileNotFoundError:
        print("[!] john çalıştırılamadı.")
        pause()
        return

    print("\n[*] Şimdiye kadar kırılan parolalar (--show):\n")
    try:
        subprocess.run([john_bin, "--show", hash_file])
    except FileNotFoundError:
        pass
    pause()


def menu_nikto(sess):
    """Nikto sarmalayıcısı: kurulu 'nikto' komutunu hedef URL'ye karşı çalıştırır."""
    nikto_bin = shutil.which("nikto")
    if not nikto_bin:
        print("""
[!] 'nikto' bu sistemde kurulu değil veya PATH'te bulunamadı.

Kurmak için:
    Debian/Ubuntu/Kali : sudo apt install nikto
    Fedora             : sudo dnf install nikto

Kurduktan sonra menüden tekrar deneyin.""")
        pause()
        return
    url = ask("Hedef URL (örn. http://192.168.1.181 veya http://site.local)")
    if not url:
        print("[!] URL boş olamaz.")
        pause()
        return
    if not ensure_authorized_url(sess, url):
        return
    run_tool([nikto_bin, "-h", url])
    pause()


def menu_gobuster(sess):
    """Gobuster (yoksa dirb) sarmalayıcısı: dizin/dosya keşfi."""
    gobuster_bin = shutil.which("gobuster")
    dirb_bin = shutil.which("dirb")
    if not gobuster_bin and not dirb_bin:
        print("""
[!] Ne 'gobuster' ne de 'dirb' bu sistemde kurulu.

Kurmak için:
    Debian/Ubuntu/Kali : sudo apt install gobuster
                     ya da: sudo apt install dirb

Kurduktan sonra menüden tekrar deneyin.""")
        pause()
        return
    url = ask("Hedef URL (örn. http://192.168.1.181/)")
    if not url:
        print("[!] URL boş olamaz.")
        pause()
        return
    if not ensure_authorized_url(sess, url):
        return
    wl_default = guess_wordlist() or "/usr/share/wordlists/dirb/common.txt"
    wl = ask("Dizin/dosya wordlist yolu", wl_default)
    if not wl or not os.path.isfile(wl):
        print("[!] Wordlist bulunamadı. 'sudo apt install dirb' ile common.txt gelir, "
              "veya seclists paketini kurabilirsiniz.")
        pause()
        return
    if gobuster_bin:
        run_tool([gobuster_bin, "dir", "-u", url, "-w", wl])
    else:
        run_tool([dirb_bin, url, wl])
    pause()


def menu_sqlmap(sess):
    """SQLMap sarmalayıcısı: varsayılan olarak düşük risk/seviyede, sadece tespit amaçlı çalışır."""
    sqlmap_bin = shutil.which("sqlmap")
    if not sqlmap_bin:
        print("""
[!] 'sqlmap' bu sistemde kurulu değil veya PATH'te bulunamadı.

Kurmak için:
    Debian/Ubuntu/Kali : sudo apt install sqlmap
    Fedora             : sudo dnf install sqlmap

Kurduktan sonra menüden tekrar deneyin.""")
        pause()
        return
    print("""
[!] SQLMap, parametre içeren URL'lere istek göndererek SQL injection test eder.
    Sadece KENDİ uygulamanız veya izinli bir CTF/lab hedefi üzerinde kullanın.
    --dump / --os-shell gibi veri çekme/komut çalıştırma seçenekleri eklemiyoruz;
    varsayılan burada sadece TESPİT (düşük risk/seviye) amaçlıdır.""")
    url = ask("Hedef URL — parametre içermeli (örn. http://192.168.1.181/sayfa.php?id=1)")
    if not url or "=" not in url:
        print("[!] URL bir parametre (örn. ?id=1) içermeli, aksi halde SQLMap test edecek bir şey bulamaz.")
        pause()
        return
    if not ensure_authorized_url(sess, url):
        return
    run_tool([sqlmap_bin, "-u", url, "--batch", "--level=1", "--risk=1"])
    pause()


def main_menu():
    sess = Session()
    print(BANNER)
    print(DISCLAIMER)
    while True:
        print("""
================= ANA MENÜ =================
 1) Hızlı tarama (sık kullanılan portlar)
 2) Özel port aralığı tara
 3) Son tarama sonuçlarını görüntüle
 4) Rapor oluştur
 5) Bilinen zafiyet referans listesini görüntüle
 6) Parola hash kırma (John the Ripper sarmalayıcı)
 7) Web zafiyet taraması (Nikto sarmalayıcı)
 8) Dizin/dosya keşfi (Gobuster/dirb sarmalayıcı)
 9) SQL injection testi (SQLMap sarmalayıcı — düşük risk)
 0) Çıkış
=============================================""")
        choice = ask("Seçiminiz", "0")
        if choice == "1":
            menu_scan(sess, None, "Hızlı tarama")
        elif choice == "2":
            spec = ask("Port listesi/aralığı (örn. 1-1000 veya 22,80,443)", "1-1000")
            menu_scan(sess, spec, "Özel port taraması")
        elif choice == "3":
            menu_view_results(sess)
        elif choice == "4":
            menu_report(sess)
        elif choice == "5":
            menu_vulndb()
        elif choice == "6":
            menu_john(sess)
        elif choice == "7":
            menu_nikto(sess)
        elif choice == "8":
            menu_gobuster(sess)
        elif choice == "9":
            menu_sqlmap(sess)
        elif choice == "0":
            print("Çıkılıyor.")
            break
        else:
            print("[!] Geçersiz seçim.")


if __name__ == "__main__":
    try:
        main_menu()
    except (KeyboardInterrupt, EOFError):
        print("\nÇıkılıyor.")
        sys.exit(0)
