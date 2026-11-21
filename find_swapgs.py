#!/usr/bin/env python3
"""
find_swapgs.py — swapgs + iretq Gadget Bulucu
Yazar: expo

vmlinux_raw icinde swapgs + iretq kombinasyonunu arar.

Kullanim:
    python3 find_swapgs.py <vmlinux_raw_dosyasi>

Aranan opcode'lar:
    swapgs → 0F 01 F8
    iretq  → 48 CF

Script, .text bölümü içinde swapgs ile başlayan ve
makul bir mesafede (<=64 byte) iretq içeren tüm adresleri listeler.

Kernel 6.17.0-5-generic için test edilmistir.
"""

import sys

TEXT_BASLANGIC_ADRES = 0xffffffff81000000
TEXT_BITIS_ADRES     = 0xffffffff82637970
TEXT_DOSYA_OFFSET    = 0x1000

SWAPGS_OPCODE = bytes([0x0F, 0x01, 0xF8])  # swapgs
IRETQ_OPCODE  = bytes([0x48, 0xCF])         # iretq

# swapgs ile iretq arasında aranacak maksimum mesafe (byte)
MAX_MESAFE = 64


def swapgs_iretq_ara(dosya_yolu: str) -> None:
    print(f"[*] swapgs (0F 01 F8) + iretq (48 CF) gadget aranıyor...")
    print(f"[*] .text aralik  : {TEXT_BASLANGIC_ADRES:#x} – {TEXT_BITIS_ADRES:#x}")
    print(f"[*] Dosya         : {dosya_yolu}\n")

    with open(dosya_yolu, "rb") as f:
        veri = f.read()

    text_uzunluk = TEXT_BITIS_ADRES - TEXT_BASLANGIC_ADRES
    text_veri    = veri[TEXT_DOSYA_OFFSET: TEXT_DOSYA_OFFSET + text_uzunluk]

    adaylar = []
    konum = 0

    while True:
        idx = text_veri.find(SWAPGS_OPCODE, konum)
        if idx == -1:
            break

        # Bu swapgs'ten sonra MAX_MESAFE byte içinde iretq var mı?
        pencere = text_veri[idx: idx + MAX_MESAFE]
        iretq_idx = pencere.find(IRETQ_OPCODE)

        if iretq_idx != -1:
            swapgs_adres = TEXT_BASLANGIC_ADRES + idx
            iretq_adres  = TEXT_BASLANGIC_ADRES + idx + iretq_idx
            adaylar.append((swapgs_adres, iretq_adres, iretq_idx))

        konum = idx + len(SWAPGS_OPCODE)

    if not adaylar:
        print("[-] Hicbir aday bulunamadi.")
        sys.exit(1)

    print(f"[+] {len(adaylar)} aday bulundu:\n")
    for swapgs_adr, iretq_adr, uzaklik in adaylar:
        print(f"  swapgs @ {swapgs_adr:#x}  |  iretq @ {iretq_adr:#x}  "
              f"(aralarinda {uzaklik} byte)")

    print(f"\n[!] En temiz adayı GDB ile doğrulayın:")
    print(f"    x/10i {adaylar[0][0]:#x}")
    print(f"\n[!] Tercih kriteri: swapgs ile iretq arasında stack bozmayan talimatlar olmalı.")
    print(f"    verw, test, jne gibi zararsız talimatlara dikkat edin.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Kullanim: {sys.argv[0]} <vmlinux_raw>")
        sys.exit(1)

    swapgs_iretq_ara(sys.argv[1])
