// rop.c — Zafiyetli LKM: kernel stack overflow
// Yazar: expo
// copy_from_user cagrisinda boyut kontrolu yapilmamasi nedeniyle stack overflow olusur

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>

#define CIHAZ_ADI "vuln_device"

static struct class*  vunl_class  = NULL;
static struct device* vunl_device = NULL;
static int major_no;

// Cihaz dosyasına herkesin erişebilmesi için izinleri 0666 yap
static char *vunl_devnode(const struct device *dev, umode_t *mode) {
    if (mode) *mode = 0666;
    return NULL;
}

// Optimizasyon kapalı: GCC bu fonksiyonun stack frame'ini değiştirmesin
__attribute__((optimize(0)))
static ssize_t device_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos) {
    char tampon[64]; // sabit 64 byte — zafiyet buradan kaynaklanıyor

    // ZAFIYET: count parametresi kontrol edilmiyor!
    // 64 byte'tan fazla veri gelirse kernel stack overflow meydana gelir.
    if (_copy_from_user(tampon, buf, count)) {
        return -EFAULT;
    }
    return count;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .write = device_write,
};

static int __init vuln_init(void) {
    major_no = register_chrdev(0, CIHAZ_ADI, &fops);
    if (major_no < 0) return major_no;

    vunl_class = class_create(CIHAZ_ADI);
    if (IS_ERR(vunl_class)) {
        unregister_chrdev(major_no, CIHAZ_ADI);
        return PTR_ERR(vunl_class);
    }

    vunl_class->devnode = vunl_devnode;
    vunl_device = device_create(vunl_class, NULL, MKDEV(major_no, 0), NULL, CIHAZ_ADI);
    printk(KERN_INFO "[+] %s modulu yuklendi, major: %d\n", CIHAZ_ADI, major_no);
    return 0;
}

static void __exit vuln_exit(void) {
    device_destroy(vunl_class, MKDEV(major_no, 0));
    class_destroy(vunl_class);
    unregister_chrdev(major_no, CIHAZ_ADI);
    printk(KERN_INFO "[-] %s modulu kaldirildi\n", CIHAZ_ADI);
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
