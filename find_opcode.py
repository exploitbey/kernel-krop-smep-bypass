#!/usr/bin/env python3
"""
find_opcode.py — vmlinux Opcode Tarayici
Yazar: expo

vmlinux_raw binary dosyasinda belirli bir opcode dizisini arar.

Kullanim:
    python3 find_opcode.py <vmlinux_raw_dosyasi> <opcode_hex>

Ornek:
    python3 find_opcode.py vmlinux_raw 5fc3
    # Yukarıdaki komut "pop rdi ; ret" gadgetını arar.

Notlar:
    - .text section aralik: 0xffffffff81000000 – 0xffffffff82637970
    - Bu aralik kernel 6.17.0-5-generic'e ozgudur.
      Farklı kernel surumlerinde degisebilir.
    - vmlinux_raw; extract-vmlinux scriptiyle vmlinuz'dan elde edilir.
"""

import sys

# --- Kernel 6.17.0-5-generic .text section sınırları ---
TEXT_BASLANGIC_ADRES = 0xffffffff81000000
TEXT_BITIS_ADRES     = 0xffffffff82637970

# vmlinux dosyasındaki .text'in başladığı dosya offseti
# (readelf -S vmlinux_raw | grep " .text" ile doğrulanabilir)
TEXT_DOSYA_OFFSET    = 0x1000  # genellikle 0x1000, kendi ortamınızda doğrulayın


def opcode_ara(dosya_yolu: str, aranan_hex: str) -> None:
    aranan_bytes = bytes.fromhex(aranan_hex)
    aranan_uzunluk = len(aranan_bytes)

    print(f"[*] Aranan opcode : {aranan_hex.upper()} ({aranan_bytes})")
    print(f"[*] .text aralik  : {TEXT_BASLANGIC_ADRES:#x} – {TEXT_BITIS_ADRES:#x}")
    print(f"[*] Dosya         : {dosya_yolu}\n")

    with open(dosya_yolu, "rb") as f:
        veri = f.read()

    text_uzunluk = TEXT_BITIS_ADRES - TEXT_BASLANGIC_ADRES
    text_veri    = veri[TEXT_DOSYA_OFFSET: TEXT_DOSYA_OFFSET + text_uzunluk]

    bulunan = 0
    konum = 0

    while True:
        idx = text_veri.find(aranan_bytes, konum)
        if idx == -1:
            break

        gercek_adres = TEXT_BASLANGIC_ADRES + idx
        print(f"  [+] Gadget bulundu: {gercek_adres:#x}")
        bulunan += 1
        konum = idx + aranan_uzunluk

    print(f"\n[*] Toplam {bulunan} adet eslesen gadget bulundu.")
    if bulunan > 0:
        print("[!] GDB ile dogrulayin: x/3i <adres>")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Kullanim: {sys.argv[0]} <vmlinux_raw> <opcode_hex>")
        print(f"Ornek  : {sys.argv[0]} vmlinux_raw 5fc3")
        sys.exit(1)

    opcode_ara(sys.argv[1], sys.argv[2])
