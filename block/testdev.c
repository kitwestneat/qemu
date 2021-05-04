#include "qemu/osdep.h"
#include <stdlib.h>
#include <linux/vfio.h>
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/cutils.h"
#include "qemu/option.h"
#include "qemu/vfio-helpers.h"
#include "block/block_int.h"
#include "sysemu/replay.h"
#include "trace.h"

#define TESTDEV_SIZE_MB_DEFAULT 1024
#define TESTDEV_BLOCK_SIZE 4096

#define MAGIC_OFFSET 282624

typedef struct TestDevState TestDevState;

struct TestDevState {
    const char *device;
    size_t size_mb;
    int64_t latency_ns;
	bool is_flushing;
	uint8_t *buf;
	struct {
		uint64_t io_size_small;
		uint64_t io_size_4096;
		uint64_t io_size_large;
		uint64_t io_size_min;
		uint64_t io_size_max;
		uint64_t iov_len_small;
		uint64_t iov_len_4096;
		uint64_t iov_len_large;
		uint64_t iov_len_min;
		uint64_t iov_len_max;
		uint64_t iov_cnt_one;
		uint64_t iov_cnt_less;
		uint64_t iov_cnt_more;
		uint64_t iov_cnt_max;
		uint64_t iov_cnt_min;
		uint64_t qd_cur;
		uint64_t qd_max;
		uint64_t qd_flush;
		uint64_t qd_flush_max;
	} stats;
};

#define TESTDEV_OPT_DEVICE "device"
#define TESTDEV_OPT_SIZE_MB "size-mb"
#define TESTDEV_OPT_LATENCY "latency-ns"

static QemuOptsList runtime_opts = {
    .name = "testdev",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = TESTDEV_OPT_DEVICE,
            .type = QEMU_OPT_STRING,
            .help = "Device ID",
        },
        {
            .name = TESTDEV_OPT_SIZE_MB,
            .type = QEMU_OPT_NUMBER,
            .help = "Device size in MB",
        },
        {
            .name = TESTDEV_OPT_LATENCY,
            .type = QEMU_OPT_NUMBER,
            .help = "nanoseconds (approximated) to wait "
                    "before completing request",
        },
        { /* end of list */ }
    },
};

/* Parse a filename in the format of testdev://deviceid[/size_in_mb]. Example:
 *
 *     testdev://my_test_device/1024
 */
static void testdev_parse_filename(const char *filename, QDict *options,
                                   Error **errp)
{
    int pref = strlen("testdev://");
    if (strlen(filename) <= pref || strncmp(filename, "testdev://", pref)) {
            return;
    }

    const char *tmp = filename + pref;
    const char *slash = strchr(tmp, '/');
    if (!slash) {
        qdict_put_str(options, TESTDEV_OPT_DEVICE, tmp);
        return;
    }

    char *device = g_strndup(tmp, slash - tmp);
    qdict_put_str(options, TESTDEV_OPT_DEVICE, device);
    g_free(device);

    const char *size_str = slash + 1;
    if (!*size_str) {
        return;
    }

    size_t sz;
    if (qemu_strtou64(size_str, NULL, 10, &sz)) {
        error_setg(errp, "Invalid namespace '%s', positive number expected",
                   size_str);
    } else {
        qdict_put_str(options, TESTDEV_OPT_SIZE_MB, size_str);
    }

}

static void testdev_close(BlockDriverState *bs)
{
    TestDevState *s = bs->opaque;
	if (s->buf)
		free(s->buf);

    return;
}

static int testdev_file_open(BlockDriverState *bs, QDict *options, int flags,
                             Error **errp)
{
    QemuOpts *opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);

    const char *device = qemu_opt_get(opts, TESTDEV_OPT_DEVICE);
    if (!device) {
        error_setg(errp, "'" TESTDEV_OPT_DEVICE "' option is required");
        qemu_opts_del(opts);
        return -EINVAL;
    }

    TestDevState *s = bs->opaque;
    s->latency_ns = qemu_opt_get_number(opts, TESTDEV_OPT_LATENCY, 0);
    if (s->latency_ns < 0) {
        error_setg(errp, "latency-ns is invalid");
        qemu_opts_del(opts);
        return -EINVAL;
    }
	printf("latency=%ld\n", s->latency_ns);
    s->size_mb = qemu_opt_get_number(opts, TESTDEV_OPT_SIZE_MB, TESTDEV_SIZE_MB_DEFAULT);
	s->buf = malloc(s->size_mb << 20);
	if (!s->buf) {
        error_setg(errp, "cannot allocate memory");
        qemu_opts_del(opts);
		return -ENOMEM;
	}

    s->device = g_strdup(device);
    qemu_opts_del(opts);

    bs->supported_write_flags = BDRV_REQ_FUA;

    return 0;
}

static int64_t testdev_getlength(BlockDriverState *bs)
{
    TestDevState *s = bs->opaque;
    return s->size_mb << 20;
}

static int testdev_probe_blocksizes(BlockDriverState *bs, BlockSizes *bsz)
{
    bsz->phys = TESTDEV_BLOCK_SIZE;
    bsz->log = TESTDEV_BLOCK_SIZE;
    return 0;
}

static coroutine_fn int testdev_co_rw(bool is_write, BlockDriverState *bs,
                                      uint64_t offset, uint64_t bytes,
                                      QEMUIOVector *qiov, int flags)
{
    TestDevState *s = bs->opaque;
	if (offset > (s->size_mb << 20))
		return -EINVAL;

	if (offset == MAGIC_OFFSET)
		return -EAGAIN;

	s->stats.qd_cur++;
	if (s->stats.qd_max < s->stats.qd_cur)
		s->stats.qd_max = s->stats.qd_cur;
	if (s->is_flushing)
		s->stats.qd_flush++;
	if (s->stats.qd_flush_max < s->stats.qd_flush)
		s->stats.qd_flush_max = s->stats.qd_flush;

    if (s->latency_ns) {
        qemu_co_sleep_ns(QEMU_CLOCK_REALTIME, s->latency_ns);
    }

	uint8_t *bufptr = s->buf + offset;
	size_t total_size = 0;

    for (int i = 0; i < qiov->niov; i++) {
        char *base = qiov->iov[i].iov_base;
        size_t len = qiov->iov[i].iov_len;
		total_size += len;

		if (len < 4096)
			s->stats.iov_len_small++;
		else if (len == 4096)
			s->stats.iov_len_4096++;
		else
			s->stats.iov_len_large++;

		if (len > s->stats.iov_len_max)
			s->stats.iov_len_max = len;

		if (len == 0)
			printf("iov len is 0 in testdev_co_rw\n");
		else if (len < s->stats.iov_len_min || s->stats.iov_len_min == 0)
			s->stats.iov_len_min = len;

		if (is_write)
			memcpy(bufptr, base, len);
		else
			memcpy(base, bufptr, len);

		bufptr += len;
    }

	s->stats.qd_cur--;

	if (total_size != bytes)
		fprintf(stderr, "total_size: %lu bytes: %lu\n", total_size, bytes);

	if (bytes < 4096)
		s->stats.io_size_small++;
	else if (bytes == 4096)
		s->stats.io_size_4096++;
	else
		s->stats.io_size_large++;

	if (bytes == 0)
		printf("iov bytes is 0 in testdev_co_rw\n");
	else if (bytes < s->stats.io_size_min || s->stats.io_size_min == 0)
		s->stats.io_size_min = bytes;

	if (bytes > s->stats.io_size_max)
		s->stats.io_size_max = bytes;

	if (qiov->niov == 1)
		s->stats.iov_cnt_one++;
	else if (qiov->niov < 5)
		s->stats.iov_cnt_less++;
	else
		s->stats.iov_cnt_more++;

	if (qiov->niov < s->stats.iov_cnt_min)
		s->stats.iov_cnt_min = qiov->niov;

	if (qiov->niov > s->stats.iov_cnt_max)
		s->stats.iov_cnt_max = qiov->niov;

    return 0;
}

static coroutine_fn int testdev_co_preadv(BlockDriverState *bs,
                                       uint64_t offset, uint64_t bytes,
                                       QEMUIOVector *qiov, int flags)
{
	return testdev_co_rw(false, bs, offset, bytes, qiov, flags);
}

static coroutine_fn int testdev_co_pwritev(BlockDriverState *bs,
                                        uint64_t offset, uint64_t bytes,
                                        QEMUIOVector *qiov, int flags)
{
	return testdev_co_rw(true, bs, offset, bytes, qiov, flags);
}

static coroutine_fn int testdev_co_flush(BlockDriverState *bs)
{
    TestDevState *s = bs->opaque;
	s->is_flushing = true;
    if (s->latency_ns) {
        qemu_co_sleep_ns(QEMU_CLOCK_REALTIME, s->latency_ns);
    }
	s->is_flushing = false;
	s->stats.qd_flush = 0;

	fprintf(stderr, "flush\n");

    return 0;
}

static int coroutine_fn testdev_co_truncate(BlockDriverState *bs, int64_t offset,
                                            bool exact, PreallocMode prealloc,
                                            BdrvRequestFlags flags, Error **errp)
{
    int64_t cur_length;

    if (prealloc != PREALLOC_MODE_OFF) {
        error_setg(errp, "Unsupported preallocation mode '%s'",
                   PreallocMode_str(prealloc));
        return -ENOTSUP;
    }

    cur_length = testdev_getlength(bs);
    if (offset != cur_length && exact) {
        error_setg(errp, "Cannot resize test devices");
        return -ENOTSUP;
    } else if (offset > cur_length) {
        error_setg(errp, "Cannot grow test devices");
        return -EINVAL;
    }

    return 0;
}

static int testdev_reopen_prepare(BDRVReopenState *reopen_state,
                               BlockReopenQueue *queue, Error **errp)
{
    return 0;
}

static void testdev_refresh_filename(BlockDriverState *bs)
{
    TestDevState *s = bs->opaque;

    snprintf(bs->exact_filename, sizeof(bs->exact_filename), "testdev://%s/%zu",
             s->device, s->size_mb);
}

static void testdev_refresh_limits(BlockDriverState *bs, Error **errp)
{
    bs->bl.opt_mem_alignment = 4096;
    bs->bl.request_alignment = 4096;
    bs->bl.max_transfer = pow2floor(BDRV_REQUEST_MAX_BYTES);
}

static BlockStatsSpecific *testdev_get_specific_stats(BlockDriverState *bs)
{
    BlockStatsSpecific *stats = g_new(BlockStatsSpecific, 1);
    TestDevState *s = bs->opaque;

	// defined in qapi
    stats->driver = BLOCKDEV_DRIVER_TESTDEV;
    stats->u.testdev = (BlockStatsSpecificTestdev) {
		.io_size_small = s->stats.io_size_small,
		.io_size_4096 = s->stats.io_size_4096,
		.io_size_large = s->stats.io_size_large,
		.io_size_min = s->stats.io_size_min,
		.io_size_max = s->stats.io_size_max,
		.iov_len_small = s->stats.iov_len_small,
		.iov_len_4096 = s->stats.iov_len_4096,
		.iov_len_large = s->stats.iov_len_large,
		.iov_len_min = s->stats.iov_len_min,
		.iov_len_max = s->stats.iov_len_max,
		.iov_cnt_one = s->stats.iov_cnt_one,
		.iov_cnt_less = s->stats.iov_cnt_less,
		.iov_cnt_more = s->stats.iov_cnt_more,
		.iov_cnt_min = s->stats.iov_cnt_min,
		.iov_cnt_max = s->stats.iov_cnt_max,
		.qd_cur = s->stats.qd_cur,
		.qd_max = s->stats.qd_max,
		.qd_flush = s->stats.qd_flush,
		.qd_flush_max = s->stats.qd_flush_max,
    };

    return stats;
}

static const char *const testdev_strong_runtime_opts[] = {
    TESTDEV_OPT_DEVICE,
    TESTDEV_OPT_SIZE_MB,

    NULL
};

static BlockDriver bdrv_testdev = {
    .format_name              = "testdev",
    .protocol_name            = "testdev",
    .instance_size            = sizeof(TestDevState),

    .bdrv_co_create_opts      = bdrv_co_create_opts_simple,
    .create_opts              = &bdrv_create_opts_simple,

    .bdrv_parse_filename      = testdev_parse_filename,
    .bdrv_file_open           = testdev_file_open,
    .bdrv_close               = testdev_close,
    .bdrv_getlength           = testdev_getlength,
    .bdrv_probe_blocksizes    = testdev_probe_blocksizes,
    .bdrv_co_truncate         = testdev_co_truncate,

    .bdrv_co_preadv           = testdev_co_preadv,
    .bdrv_co_pwritev          = testdev_co_pwritev,

    .bdrv_co_flush_to_disk    = testdev_co_flush,
    .bdrv_reopen_prepare      = testdev_reopen_prepare,

    .bdrv_refresh_filename    = testdev_refresh_filename,
    .bdrv_refresh_limits      = testdev_refresh_limits,
    .strong_runtime_opts      = testdev_strong_runtime_opts,
    .bdrv_get_specific_stats  = testdev_get_specific_stats,
};

static void bdrv_testdev_init(void)
{
    bdrv_register(&bdrv_testdev);
}

block_init(bdrv_testdev_init);
