#!/usr/bin/env python3
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

                    made by EFE KUŞCU
"""

DISCLAIMER = """\
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


def list_interfaces():
    """/sys/class/net üzerinden ağ arayüzü adlarını listeler (ek paket gerekmez)."""
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


def menu_wireshark_gui():
    ws_bin = shutil.which("wireshark")
    if not ws_bin:
        print("""
[!] 'wireshark' bu sistemde kurulu değil veya PATH'te bulunamadı.

Kurmak için:
    Debian/Ubuntu/Kali : sudo apt install wireshark
    Fedora             : sudo dnf install wireshark

Kurulumda "non-root kullanıcıların paket yakalamasına izin ver" sorusuna
evet derseniz sudo'suz da kullanabilirsiniz. Kurduktan sonra tekrar deneyin.""")
        pause()
        return
    ifaces = list_interfaces()
    if ifaces:
        print(f"\nBulunan arayüzler: {', '.join(ifaces)}")
    iface = ask("Dinlenecek arayüz (boş bırakırsanız Wireshark'ın kendi seçim ekranı açılır)", "")
    cmd = [ws_bin] + (["-i", iface, "-k"] if iface else [])
    run_tool(cmd)


def menu_tshark_capture():
    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        print("""
[!] 'tshark' bu sistemde kurulu değil veya PATH'te bulunamadı.

Kurmak için:
    Debian/Ubuntu/Kali : sudo apt install tshark
    Fedora             : sudo dnf install wireshark-cli

Kurduktan sonra tekrar deneyin. (Not: 'tshark' genelde wireshark paketiyle
birlikte de gelir.)""")
        pause()
        return
    ifaces = list_interfaces()
    if ifaces:
        print(f"\nBulunan arayüzler: {', '.join(ifaces)}")
    iface = ask("Dinlenecek arayüz", ifaces[0] if ifaces else "eth0")
    bpf = ask("BPF filtresi (opsiyonel, örn. 'tcp port 80')", "")
    count = ask("Kaç paket sonra dursun (boş = Ctrl+C ile siz durdurana kadar)", "")
    save = ask("Bir .pcap dosyasına kaydedilsin mi? Dosya adı (boş = sadece ekrana yazdır)", "")

    cmd = [tshark_bin, "-i", iface]
    if bpf:
        cmd += ["-f", bpf]
    if count:
        cmd += ["-c", count]
    if save:
        cmd += ["-w", save]

    print("""
[!] Paket yakalama, o ağdaki trafiği (içeriğiyle birlikte) görüntüler.
    Sadece kendi ağınızda / kendi trafiğinizi incelemek ya da izinli bir
    lab ortamında kullanın. Başkalarının trafiğini onay almadan
    izlemek/kaydetmek yasa dışı olabilir.""")
    ans = input("Devam etmek için EVET yazın: ")
    if ans.strip() != "EVET":
        print("Onaylanmadı, çıkılıyor.")
        pause()
        return
    run_tool(cmd)
    if save:
        print(f"\n[+] Kayıt dosyası: {save} (Wireshark ile açıp inceleyebilirsiniz)")
    pause()


def submenu_traffic():
    while True:
        print("""
======= AĞ TRAFİĞİ ANALİZİ (Wireshark) =======
 1) Wireshark'ı grafik arayüzle başlat
 2) tshark ile komut satırından paket yakala
 0) Ana menüye dön
================================================""")
        c = ask("Seçiminiz", "0")
        if c == "1":
            menu_wireshark_gui()
        elif c == "2":
            menu_tshark_capture()
        elif c == "0":
            return
        else:
            print("[!] Geçersiz seçim.")


def menu_theharvester():
    th_bin = shutil.which("theHarvester") or shutil.which("theharvester")
    if not th_bin:
        print("""
[!] 'theHarvester' bu sistemde kurulu değil veya PATH'te bulunamadı.

Kurmak için:
    Debian/Ubuntu/Kali : sudo apt install theharvester
    Diğer              : pip install theHarvester  (veya GitHub'dan klonlayın)

Kurduktan sonra tekrar deneyin.""")
        pause()
        return
    print("""
[!] theHarvester, bir domain hakkında arama motorları/sertifika kayıtları
    gibi HALKA AÇIK kaynaklardan e-posta/subdomain/isim toplar — sızma
    yapmaz, sadece zaten herkese açık bilgiyi derler. Yine de sadece
    kendi domain'iniz veya izinli bir hedef için kullanın.""")
    domain = ask("Hedef domain (örn. example.com)")
    if not domain:
        print("[!] Domain boş olamaz.")
        pause()
        return
    source = ask("Kaynak (örn. google, bing, crtsh, duckduckgo — 'all' da yazılabilir ama bazı sürümlerde yavaş/sorunlu olabilir)", "crtsh")
    limit = ask("Sonuç limiti", "200")
    run_tool([th_bin, "-d", domain, "-b", source, "-l", limit])
    pause()


def menu_steghide():
    sh_bin = shutil.which("steghide")
    if not sh_bin:
        print("""
[!] 'steghide' bu sistemde kurulu değil veya PATH'te bulunamadı.

Kurmak için:
    Debian/Ubuntu/Kali : sudo apt install steghide

Kurduktan sonra tekrar deneyin.""")
        pause()
        return
    print("""
======= STEGHIDE =======
 1) Veri çıkar (extract) — bir resim/ses dosyasına gizlenmiş veriyi çıkarır
 2) Veri gizle (embed)   — bir dosyayı resim/ses dosyasının içine gizler
 0) Geri
=========================""")
    c = ask("Seçiminiz", "0")
    if c == "1":
        cover = ask("İçinde gizli veri olduğunu düşündüğünüz dosya (örn. resim.jpg)")
        if not cover or not os.path.isfile(cover):
            print("[!] Dosya bulunamadı.")
            pause()
            return
        print("[*] Parola soracak (biliyorsanız girin, bilmiyorsanız boş bırakıp Enter'a basmayı deneyebilirsiniz).")
        run_tool([sh_bin, "extract", "-sf", cover])
    elif c == "2":
        cover = ask("Taşıyıcı dosya (örn. resim.jpg)")
        secret = ask("Gizlenecek dosya (örn. gizli.txt)")
        out = ask("Çıktı dosya adı", "cikti.jpg")
        if not cover or not os.path.isfile(cover) or not secret or not os.path.isfile(secret):
            print("[!] Dosyalardan biri bulunamadı.")
            pause()
            return
        run_tool([sh_bin, "embed", "-cf", cover, "-ef", secret, "-sf", out])
    else:
        return
    pause()


def submenu_osint():
    while True:
        print("""
========== OSINT / ADLİ ANALİZ ARAÇLARI ==========
 1) theHarvester (e-posta/subdomain toplama)
 2) Steghide (steganografi — veri çıkar/gizle)
 0) Ana menüye dön
====================================================""")
        c = ask("Seçiminiz", "0")
        if c == "1":
            menu_theharvester()
        elif c == "2":
            menu_steghide()
        elif c == "0":
            return
        else:
            print("[!] Geçersiz seçim.")


def submenu_recon(sess):
    while True:
        print("""
========== AĞ KEŞİF ARAÇLARI ==========
 1) Hızlı tarama (sık kullanılan portlar)
 2) Özel port aralığı tara
 3) Son tarama sonuçlarını görüntüle
 4) Rapor oluştur
 0) Ana menüye dön
========================================""")
        c = ask("Seçiminiz", "0")
        if c == "1":
            menu_scan(sess, None, "Hızlı tarama")
        elif c == "2":
            spec = ask("Port listesi/aralığı (örn. 1-1000 veya 22,80,443)", "1-1000")
            menu_scan(sess, spec, "Özel port taraması")
        elif c == "3":
            menu_view_results(sess)
        elif c == "4":
            menu_report(sess)
        elif c == "0":
            return
        else:
            print("[!] Geçersiz seçim.")


def submenu_password(sess):
    while True:
        print("""
============ PAROLA ARAÇLARI ============
 1) Parola hash kırma (John the Ripper)
 0) Ana menüye dön
==========================================""")
        c = ask("Seçiminiz", "0")
        if c == "1":
            menu_john(sess)
        elif c == "0":
            return
        else:
            print("[!] Geçersiz seçim.")


def submenu_web(sess):
    while True:
        print("""
========== WEB UYGULAMA ARAÇLARI ==========
 1) Web zafiyet taraması (Nikto)
 2) Dizin/dosya keşfi (Gobuster/dirb)
 3) SQL injection testi (SQLMap — düşük risk)
 0) Ana menüye dön
============================================""")
        c = ask("Seçiminiz", "0")
        if c == "1":
            menu_nikto(sess)
        elif c == "2":
            menu_gobuster(sess)
        elif c == "3":
            menu_sqlmap(sess)
        elif c == "0":
            return
        else:
            print("[!] Geçersiz seçim.")


def main_menu():
    sess = Session()
    print(BANNER)
    print(DISCLAIMER)
    while True:
        print("""
================= ANA MENÜ =================
 1) Ağ Keşif Araçları
 2) Parola Araçları
 3) Web Uygulama Araçları
 4) Ağ Trafiği Analizi (Wireshark/tshark)
 5) OSINT / Adli Analiz Araçları
 0) Çıkış
=============================================""")
        choice = ask("Seçiminiz", "0")
        if choice == "1":
            submenu_recon(sess)
        elif choice == "2":
            submenu_password(sess)
        elif choice == "3":
            submenu_web(sess)
        elif choice == "4":
            submenu_traffic()
        elif choice == "5":
            submenu_osint()
        elif choice == "0":
            print("""
Çıkılıyor.

    Thanks for using my tool.
    And don't forget they are watching u.
""")
            break
        else:
            print("[!] Geçersiz seçim.")


if __name__ == "__main__":
    try:
        main_menu()
    except (KeyboardInterrupt, EOFError):
        print("""
Çıkılıyor.

    Thanks for using my tool.
    And don't forget they are watching u.
""")
        sys.exit(0)
