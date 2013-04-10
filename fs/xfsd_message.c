#include "xfsd.h"

#include "xfs/xfs_fs.h"
#include "xfs/xfs_types.h"
#include "xfs/xfs_log.h"
#include "xfs/xfs_trans.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"

#include "xfsd_message.h"

#define define_xfs_printk_level(func, kern_level)		\
void func(const struct xfs_mount *mp, const char *fmt, ...)	\
{}
/*
{								\
	struct va_format	vaf;				\
	va_list			args;				\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	__xfs_printk(kern_level, mp, &vaf);			\
	va_end(args);						\
}								\
*/


define_xfs_printk_level(xfs_emerg, KERN_EMERG);
define_xfs_printk_level(xfs_alert, KERN_ALERT);
define_xfs_printk_level(xfs_crit, KERN_CRIT);
define_xfs_printk_level(xfs_err, KERN_ERR);
define_xfs_printk_level(xfs_warn, KERN_WARNING);
define_xfs_printk_level(xfs_notice, KERN_NOTICE);
define_xfs_printk_level(xfs_info, KERN_INFO);
#ifdef DEBUG
define_xfs_printk_level(xfs_debug, KERN_DEBUG);
#endif

void
xfs_alert_tag(
	const struct xfs_mount	*mp,
	int			panic_tag,
	const char		*fmt, ...)
{
	/*
	struct va_format	vaf;
	va_list			args;
	int			do_panic = 0;

	if (xfs_panic_mask && (xfs_panic_mask & panic_tag)) {
		xfs_alert(mp, "Transforming an alert into a BUG.");
		do_panic = 1;
	}

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	__xfs_printk(KERN_ALERT, mp, &vaf);
	va_end(args);

	BUG_ON(do_panic);
	*/
}

void
assfail(char *expr, char *file, int line)
{
	/*
	xfs_emerg(NULL, "Assertion failed: %s, file: %s, line: %d",
		expr, file, line);
	BUG();
	*/
}

void
xfs_hex_dump(void *p, int length)
{
	/*
	print_hex_dump(KERN_ALERT, "", DUMP_PREFIX_ADDRESS, 16, 1, p, length, 1);
	*/
}
