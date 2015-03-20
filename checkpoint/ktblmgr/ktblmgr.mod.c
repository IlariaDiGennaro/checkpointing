#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x8479aeaa, "module_layout" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x3eb855fc, "per_cpu__current_task" },
	{ 0x1b67fce8, "kmalloc_caches" },
	{ 0x9b388444, "get_zeroed_page" },
	{ 0x7e5e301f, "unregister_kprobe" },
	{ 0x93260715, "register_kprobe" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0x4e5304d4, "__register_chrdev" },
	{ 0x4187fd9c, "rootsim_pager" },
	{ 0x358acced, "mutex_unlock" },
	{ 0x1ee0937f, "__mutex_init" },
	{ 0xea147363, "printk" },
	{ 0x6383fc37, "mutex_lock" },
	{ 0xfd97d887, "kmem_cache_alloc" },
	{ 0xe4c1ff49, "__free_pages" },
	{ 0xe52947e7, "__phys_addr" },
	{ 0x4302d0eb, "free_pages" },
	{ 0x37a0cba, "kfree" },
	{ 0xe19b9388, "pv_mmu_ops" },
	{ 0x9842fb58, "rootsim_load_cr3" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

