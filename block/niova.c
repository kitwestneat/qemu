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

#include <niova/common.h>
#include <niova/niorq_mgr.h>
#include <niova/nclient.h>

#define NIOVADEV_DEFAULT_FILE_SIZE ((size_t)1 << 31)
#define NIOVADEV_BLOCK_SIZE 4096
#define NIOVADEV_MAX_XFER_BLKS 1024
#define NIOVADEV_MAX_IOV 512
#define NIOVADEV_REQ_OPTS 0

typedef struct NiovaDevState NiovaDevState;

struct io_processor_mgr_opts niovaDevDefaultOpts = {
    .iopmo_file_name = "./niova-block-test.img",
    .iopmo_queue_depth = 256,
    .iopmo_is_server = 0,
    .iopmo_directio = 0,
    .iopmo_memalign = 0,
    .iopmo_bufs_registered = 0,
    .iopmo_files_registered = 0,
    .iopmo_touch_pages = 0,
    .iopmo_no_sgl = 0,
    .iopmo_lat_measure_freq = 0, // default - every time
    .iopmo_net_only = 0,
    .iopmo_mmap = 0,
    .iopmo_conn_credits = CONN_HANDLE_DEF_CREDITS,
    .iopmo_uring_entries = URING_ENTRIES_DEF,
    .iopmo_file_size = NIOVADEV_DEFAULT_FILE_SIZE,
    .iopmo_buf_sizes_in_blks = {SMALL_NBLKS, MEDIUM_NBLKS, LARGE_NBLKS},
    .iopmo_buf_counts = {SMALL_NBUFS, MEDIUM_NBUFS, LARGE_NBUFS},
};

struct NiovaDevState {
	niova_block_client_t *client;
	// uuid_t uuid; should use target_uuid on the opts
	struct io_processor_mgr_opts niova_opts;
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
	} stats;
};

#define NIOVA_OPT_FILE_NAME "file-name"
#define NIOVA_OPT_UUID "uuid"
#define NIOVA_OPT_QUEUE_DEPTH "queue-depth"

static QemuOptsList runtime_opts = {
    .name = "niova",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = NIOVA_OPT_FILE_NAME,
            .type = QEMU_OPT_STRING,
            .help = "Backing File",
        },
        {
            .name = NIOVA_OPT_UUID,
            .type = QEMU_OPT_STRING,
            .help = "UUID",
        },
        {
            .name = NIOVA_OPT_QUEUE_DEPTH,
            .type = QEMU_OPT_NUMBER,
            .help = "Queue Depth",
        },
        { /* end of list */ }
    },
};

/* Parse a filename in the format of niova://[filename][#queue_depth]. Example:
 *
 *     niova://uuid/./niova-block.img#32
 */
static void niovadev_parse_filename(const char *filename, QDict *options,
                                   Error **errp)
{
    int pref = strlen("niova://");
    if (strlen(filename) <= pref || strncmp(filename, "niova://", pref)) {
            return;
    }

    const char *pref_end = filename + pref;
    const char *slash = strchr(pref_end, '/');
    const char *pound = strchr(slash ? slash : pref_end, '#');
	const char *uuid_end = slash ? slash : pound;
    if (!uuid_end) {
        qdict_put_str(options, NIOVA_OPT_UUID, pref_end);
        return;
    }

	char *uuid = g_strndup(pref_end, uuid_end - pref_end);
	qdict_put_str(options, NIOVA_OPT_UUID, uuid);
	g_free(uuid);

	if (slash) {
		const char *fn_str = slash + 1;
		if (*fn_str) {
			if (!pound) {
				qdict_put_str(options, NIOVA_OPT_FILE_NAME, fn_str);
				return;
			}
			if (fn_str != pound) {
				void *fn = g_strndup(fn_str, pound - fn_str);
				qdict_put_str(options, NIOVA_OPT_FILE_NAME, fn);
				g_free(fn);
			}
		}
	}

	if (!pound)
		return;

	const char *qd_str = pound + 1;
	if (!*qd_str)
		return;

	long qd;
	if (qemu_strtol(qd_str, NULL, 10, &qd)) {
		error_setg(errp, "Invalid queue depth '%s', positive number expected",
				   qd_str);
	} else {
		qdict_put_int(options, NIOVA_OPT_QUEUE_DEPTH, qd);
	}
}

static void niovadev_close(BlockDriverState *bs)
{
    NiovaDevState *s = bs->opaque;
	if (s->client)
		NiovaBlockClientDestroy(s->client);

    return;
}

static int niova_client_setup(NiovaDevState *s) {
	return NiovaBlockClientNew(&s->client, &s->niova_opts);
}

static int niovadev_file_open(BlockDriverState *bs, QDict *options, int flags,
                             Error **errp)
{
    QemuOpts *opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);

    NiovaDevState *s = bs->opaque;
	s->niova_opts = niovaDevDefaultOpts;

	// XXX do these strdups need to be freed?
    const char *uuid = qemu_opt_get(opts, NIOVA_OPT_UUID);
    if (uuid)
		uuid_parse(uuid, s->niova_opts.iopmo_target_uuid);
    const char *device = qemu_opt_get(opts, NIOVA_OPT_FILE_NAME);
    if (device)
		s->niova_opts.iopmo_file_name = g_strdup(device);

	int qd = qemu_opt_get_number(opts, NIOVA_OPT_QUEUE_DEPTH, 0);
    if (qd > 0)
		s->niova_opts.iopmo_queue_depth = qd;

	int rc = niova_client_setup(s);
	if (rc || !s->client) {
		error_setg(errp, "niova_client_setup(): %s", strerror(-rc));
		return rc;
	}

    bs->supported_write_flags = BDRV_REQ_FUA;

    return 0;
}

static int64_t niovadev_getlength(BlockDriverState *bs)
{
    NiovaDevState *s = bs->opaque;
    return s->niova_opts.iopmo_file_size;
}

static int niovadev_probe_blocksizes(BlockDriverState *bs, BlockSizes *bsz)
{
    bsz->phys = NIOVADEV_BLOCK_SIZE;
    bsz->log = NIOVADEV_BLOCK_SIZE;
    return 0;
}

struct niovadev_cb_data {
    Coroutine *co;
	ssize_t ret;
    AioContext *ctx;
};

// qemu context
static void niovadev_rw_cb_bh(void *arg)
{
	struct niovadev_cb_data *data = arg;
    if (!data->co) {
		aio_bh_schedule_oneshot(data->ctx, niovadev_rw_cb_bh, data);
    } else {
		qemu_coroutine_enter(data->co);
	}
}

// niova context
static void niovadev_rw_cb(void *arg, ssize_t rc) {
	struct niovadev_cb_data *data = arg;
	data->ret = rc;
    aio_bh_schedule_oneshot(data->ctx, niovadev_rw_cb_bh, data);
}

static coroutine_fn int niovadev_co_rw(bool is_write, BlockDriverState *bs,
                                      int64_t start_512_blk, int nblk,
                                      QEMUIOVector *qiov)
{
    NiovaDevState *s = bs->opaque;
	if (start_512_blk % 8) {
		fprintf(stderr, "startblk not aligned %ld\n", start_512_blk);
		return -EINVAL;
	}

	// QEMU uses 512 byte blocks even if device uses 4k blocks
	int64_t start_blk = start_512_blk / 8;
	if (start_blk > s->niova_opts.iopmo_file_size) {
		fprintf(stderr, "startblk %ld max block: %ld\n", start_blk, s->niova_opts.iopmo_file_size / 512);
		return -EINVAL;
	}

	s->stats.qd_cur++;
	if (s->stats.qd_max < s->stats.qd_cur)
		s->stats.qd_max = s->stats.qd_cur;

	struct niovadev_cb_data cb_data = {
        .ctx = bdrv_get_aio_context(bs),
		.ret = -EINPROGRESS,
	};

	fprintf(stderr, "niova %s 4k sblk %ld 512 nblk %d niov %d iov[0].len %zu\n", is_write ? "write" : "read", start_blk, nblk,
			qiov->niov, qiov->iov[0].iov_len);

	int rc;
	if (is_write)
		rc = NiovaBlockClientWritev(s->client, s->niova_opts.iopmo_target_uuid,
				start_blk, qiov->iov,
				qiov->niov, niovadev_rw_cb,
				(void *)&cb_data, NIOVADEV_REQ_OPTS);
	else
		rc = NiovaBlockClientReadv(s->client, s->niova_opts.iopmo_target_uuid,
				start_blk, qiov->iov,
				qiov->niov, niovadev_rw_cb,
				(void *)&cb_data, NIOVADEV_REQ_OPTS);

	// XXX deal with errors properly
	if (rc < 0) {
		fprintf(stderr, "niova error, rc=%d\n", rc);
		return rc;
	}

	cb_data.co = qemu_coroutine_self();
    AioContext *co_ctx = qemu_coroutine_get_aio_context(cb_data.co);
	fprintf(stderr, "yielding, equal ctx? %s\n", co_ctx == cb_data.ctx ? "yes" : "no");
	do {
        qemu_coroutine_yield();
    } while (cb_data.ret == -EINPROGRESS);
	fprintf(stderr, "done yielding, ret=%zd\n", cb_data.ret);
	s->stats.qd_cur--;

	unsigned long expected = 0;
	for (int i = 0; i < qiov->niov; i++) {
		expected += qiov->iov[i].iov_len;
	}

	unsigned long bytes = (unsigned long)nblk * 512;
	if (cb_data.ret != nblk * 512)
		fprintf(stderr, "warn total_size: %lu expected: %lu bytes: %lu niov: %d\n", cb_data.ret, expected, bytes, qiov->niov);

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

static coroutine_fn int niovadev_co_readv(BlockDriverState *bs,
										  int64_t start_blk,
										  int nblk,
										  QEMUIOVector *qiov)
{
	return niovadev_co_rw(false, bs, start_blk, nblk, qiov);
}

static coroutine_fn int niovadev_co_writev(BlockDriverState *bs,
										  int64_t start_blk,
										  int nblk,
										  QEMUIOVector *qiov, int flags)
{
	return niovadev_co_rw(true, bs, start_blk, nblk, qiov);
}

static coroutine_fn int niovadev_co_flush(BlockDriverState *bs)
{
	// XXX: todo

    return 0;
}

static int coroutine_fn niovadev_co_truncate(BlockDriverState *bs, int64_t offset,
                                            bool exact, PreallocMode prealloc,
                                            BdrvRequestFlags flags, Error **errp)
{
	// XXX: todo
    return 0;
}

static int coroutine_fn niovadev_co_pdiscard(BlockDriverState *bs,
                                             int64_t offset,
                                             int bytes)
{
	fprintf(stderr, "discard: offset %ld bytes %d\n", offset, bytes);
	return 0;
}

static int niovadev_reopen_prepare(BDRVReopenState *reopen_state,
                               BlockReopenQueue *queue, Error **errp)
{
    return 0;
}

static void niovadev_refresh_filename(BlockDriverState *bs)
{
    NiovaDevState *s = bs->opaque;
	char uuid_str[UUID_STR_LEN] = {0};

	uuid_unparse(s->niova_opts.iopmo_target_uuid, uuid_str);

    snprintf(bs->exact_filename, sizeof(bs->exact_filename), "niova://%s/%s#%zu",
             uuid_str, s->niova_opts.iopmo_file_name, s->niova_opts.iopmo_queue_depth);
}

static void niovadev_refresh_limits(BlockDriverState *bs, Error **errp)
{
    bs->bl.opt_mem_alignment = NIOVADEV_BLOCK_SIZE;
    bs->bl.request_alignment = NIOVADEV_BLOCK_SIZE;
	bs->bl.pdiscard_alignment = NIOVADEV_BLOCK_SIZE;
    bs->bl.max_transfer = NIOVADEV_MAX_XFER_BLKS * NIOVADEV_BLOCK_SIZE;
	bs->bl.max_iov = NIOVADEV_MAX_IOV;
    bs->bl.max_pdiscard = QEMU_ALIGN_DOWN(INT_MAX, NIOVADEV_BLOCK_SIZE);
}

static BlockStatsSpecific *niovadev_get_specific_stats(BlockDriverState *bs)
{
    BlockStatsSpecific *stats = g_new(BlockStatsSpecific, 1);
    NiovaDevState *s = bs->opaque;

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
    };

    return stats;
}

static const char *const niovadev_strong_runtime_opts[] = {
    NIOVA_OPT_FILE_NAME,
    NIOVA_OPT_UUID,
    NIOVA_OPT_QUEUE_DEPTH,

    NULL
};

static BlockDriver bdrv_testdev = {
    .format_name              = "niova",
    .protocol_name            = "niova",
    .instance_size            = sizeof(NiovaDevState),

    .bdrv_co_create_opts      = bdrv_co_create_opts_simple,
    .create_opts              = &bdrv_create_opts_simple,

    .bdrv_parse_filename      = niovadev_parse_filename,
    .bdrv_file_open           = niovadev_file_open,
    .bdrv_close               = niovadev_close,
    .bdrv_getlength           = niovadev_getlength,
    .bdrv_probe_blocksizes    = niovadev_probe_blocksizes,
    .bdrv_co_truncate         = niovadev_co_truncate,
    .bdrv_co_pdiscard         = niovadev_co_pdiscard,

    .bdrv_co_readv           = niovadev_co_readv,
    .bdrv_co_writev          = niovadev_co_writev,

    .bdrv_co_flush_to_disk    = niovadev_co_flush,
    .bdrv_reopen_prepare      = niovadev_reopen_prepare,

    .bdrv_refresh_filename    = niovadev_refresh_filename,
    .bdrv_refresh_limits      = niovadev_refresh_limits,
    .strong_runtime_opts      = niovadev_strong_runtime_opts,
    .bdrv_get_specific_stats  = niovadev_get_specific_stats,
};

static void bdrv_testdev_init(void)
{
    bdrv_register(&bdrv_testdev);
}

block_init(bdrv_testdev_init);
