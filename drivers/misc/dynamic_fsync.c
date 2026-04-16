#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kobject.h>

/* Global toggle - enabled by default */
bool dynamic_fsync_active = true;
EXPORT_SYMBOL(dynamic_fsync_active);

static ssize_t dyn_fsync_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	return sprintf(buf, "%u\n", dynamic_fsync_active);
}

static ssize_t dyn_fsync_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
	unsigned int input;
	if (sscanf(buf, "%u", &input) != 1) return -EINVAL;
	dynamic_fsync_active = !!input;
	return count;
}

static struct kobj_attribute dyn_fsync_attribute = __ATTR(Dynamic_fsync, 0644, dyn_fsync_show, dyn_fsync_store);

static int __init dynamic_fsync_init(void) {
	return sysfs_create_file(kernel_kobj, &dyn_fsync_attribute.attr);
}

device_initcall(dynamic_fsync_init);
