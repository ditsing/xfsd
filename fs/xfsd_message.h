#ifndef __XFSD_MESSAGE_H__
#define __XFSD_MESSAGE_H__

struct xfs_mount;

extern void xfs_emerg(const struct xfs_mount *mp, const char *fmt, ...);
extern void xfs_alert(const struct xfs_mount *mp, const char *fmt, ...);
extern void xfs_alert_tag(const struct xfs_mount *mp, int tag, const char *fmt, ...);
extern void xfs_crit(const struct xfs_mount *mp, const char *fmt, ...);
extern void xfs_err(const struct xfs_mount *mp, const char *fmt, ...);
extern void xfs_warn(const struct xfs_mount *mp, const char *fmt, ...);
extern void xfs_notice(const struct xfs_mount *mp, const char *fmt, ...);
extern void xfs_info(const struct xfs_mount *mp, const char *fmt, ...);

#ifdef DEBUG
extern void xfs_debug(const struct xfs_mount *mp, const char *fmt, ...);
#endif

extern void assfail(char *expr, char *f, int l);

extern void xfs_hex_dump(void *p, int length);


#endif
