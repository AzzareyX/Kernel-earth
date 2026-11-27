#!/usr/bin/env python3
"""
Resolver konflik merge CIP v4.19.325-cip137 -> LineageOS earth lineage-23.2.
Jalankan dari root kernel tree saat MERGE_HEAD masih ada.

Usage:
    python3 scripts/resolve-cip-conflicts.py .

Kebijakan:
  ours   = patch Android/LineageOS/MediaTek dipertahankan
  theirs = fix upstream CIP diambil apa adanya
  both   = keduanya digabung
  text   = resolusi eksplisit (KABI / lock / lockdep disesuaikan)

Script akan BERHENTI jika ada blok konflik yang tidak cocok dengan aturan,
supaya tidak ada resolusi yang ditebak secara membabi buta.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
PAT = re.compile(r"(?ms)^<<<<<<< HEAD\n(.*?)^=======\n(.*?)^>>>>>>>[^\n]*\n")


def R(needle, kind, value=None):
    return (needle, kind, value)


RULES = {
    # --- DRM / virtio: ambil API GEM upstream, jangan pakai ulang path lama ---
    "drivers/gpu/drm/virtio/virtgpu_ioctl.c": [
        R("drm_gem_object_release(obj)", "text",
          "\t\tdrm_gem_object_put_unlocked(obj);\n"),
    ],

    # --- input: HEAD sudah pakai input_get_timestamp(clk_type) ---
    "drivers/input/evdev.c": [
        R("ktime_get_boottime", "ours"),
    ],

    # --- stmmac: MTK butuh RBUE|TBUE pada mask interrupt default ---
    "drivers/net/ethernet/stmicro/stmmac/dwxgmac2.h": [
        R("XGMAC_DMA_INT_DEFAULT_EN", "ours"),
    ],

    # --- stmmac: ikuti prototype callback upstream ---
    "drivers/net/ethernet/stmicro/stmmac/ring_mode.c": [
        R("rx_q->priv_data", "theirs"),
    ],

    # --- functionfs: Android butuh opened/error flags ---
    "drivers/usb/gadget/function/f_fs.c": [
        R("smp_mb__before_atomic", "ours"),
    ],

    # --- hid: HACK vendor DITAMBAH refcnt upstream ---
    "drivers/usb/gadget/function/f_hid.c": [
        R("hidg->report_desc = kmemdup", "both"),
    ],

    # --- udc/core: sysfs link vendor + teardown lockdep upstream ---
    "drivers/usb/gadget/udc/core.c": [
        R("sysfs_remove_link(&udc->dev.kobj", "text",
          "\t/*\n"
          "\t * Set the teardown flag before flushing the work to prevent new work\n"
          "\t * from being scheduled while we are cleaning up.\n"
          "\t */\n"
          "\tspin_lock_irqsave(&gadget->state_lock, flags);\n"
          "\tgadget->teardown = true;\n"
          "\tspin_unlock_irqrestore(&gadget->state_lock, flags);\n"
          "\tsysfs_remove_link(&udc->dev.kobj, \"gadget\");\n"),
        R("spin_lock_irqsave(&gadget->state_lock", "theirs"),
    ],

    # --- xhci: grace period SS roothub upstream ---
    "drivers/usb/host/xhci-hub.c": [
        R("run_graceperiod", "theirs"),
    ],

    # --- fs/Makefile: Android fs_context + upstream fs_types ---
    "fs/Makefile": [
        R("fs_context.o", "text", "\t\tfs_context.o fs_parser.o fs_types.o\n"),
    ],

    # --- f2fs: log Android + semantics readonly upstream ---
    # f2fs_msg(sb, ...) TIDAK ada di vendor tree ini; pakai f2fs_err(sbi,...).
    # Jangan tutup `if (err > 0)` di sini: context setelah marker sudah
    # menyediakan `\t\t}` dan `\t}`. `}` ekstra menutup f2fs_fill_super lebih
    # awal dan membuat semua label cleanup jadi "tidak terdefinisi".
    "fs/f2fs/super.c": [
        R("Need to recover fsync data", "text",
          "\t\tif (err > 0) {\n"
          "\t\t\tif (!f2fs_readonly(sb)) {\n"
          "\t\t\t\tf2fs_err(sbi, \"Need to recover fsync data\");\n"
          "\t\t\t\terr = -EINVAL;\n"
          "\t\t\t\tgoto free_meta;\n"
          "\t\t\t} else {\n"
          "\t\t\t\tf2fs_err(sbi, \"drop all fsynced data (readonly)\");\n"
          "\t\t\t\terr = 0;\n"
          "\t\t\t}"),
    ],

    # --- f2fs sysfs: helper upstream + atribut Android + iostat khusus ---
    "fs/f2fs/sysfs.c": [
        R("avg_vblocks_show", "both"),
        R("return sprintf(buf, \"%u\\n\", *ui);", "theirs"),
        R("iostat_period_ms", "text",
          "\tif (!strcmp(a->attr.name, \"iostat_period_ms\")) {\n"
          "\t\tif (t < MIN_IOSTAT_PERIOD_MS || t > MAX_IOSTAT_PERIOD_MS)\n"
          "\t\t\treturn -EINVAL;\n"
          "\t\tspin_lock(&sbi->iostat_lock);\n"
          "\t\tsbi->iostat_period_ms = (unsigned int)t;\n"
          "\t\tspin_unlock(&sbi->iostat_lock);\n"
          "\t\treturn count;\n"
          "\t}\n"
          "\n"
          "\t__sbi_store_value(a, sbi, ptr + a->offset, t);\n"),
    ],

    # --- jbd2: anotasi lockdep upstream ---
    "fs/jbd2/transaction.c": [
        R("rwsem_acquire_read", "theirs"),
    ],

    # --- bpf.h: aux Android + owner field upstream ---
    "include/linux/bpf.h": [
        R("owner_prog_type", "text",
          "\tstruct bpf_array_aux *aux;\n"
          "\t/* 'ownership' of prog_array is claimed by the first program that\n"
          "\t * is going to use this map or by the first program which FD is stored\n"
          "\t * in the map to make sure that all callers and callees have the same\n"
          "\t * prog_type and JITed flag\n"
          "\t */\n"
          "\tenum bpf_prog_type owner_prog_type;\n"
          "\tbool owner_jited;\n"
          "\tenum bpf_attach_type owner_attach_type;\n"),
    ],

    # --- fs.h: dua include harus sama-sama ada ---
    "include/linux/fs.h": [
        R("android_kabi.h", "text",
          "#include <linux/android_kabi.h>\n#include <linux/fs_types.h>\n"),
    ],

    # --- sock.h: sk_owner masuk KABI reserve #2, jangan ubah ukuran struct ---
    "include/net/sock.h": [
        R("ANDROID_KABI_USE(1, spinlock_t sk_peer_lock)", "text",
          "#if IS_ENABLED(CONFIG_DEBUG_SPINLOCK) || IS_ENABLED(CONFIG_DEBUG_LOCK_ALLOC)\n"
          "\tANDROID_KABI_RESERVE(1);\n"
          "#else\n"
          "\tANDROID_KABI_USE(1, spinlock_t sk_peer_lock);\n"
          "#endif\n"
          "#if IS_ENABLED(CONFIG_PROVE_LOCKING) && IS_ENABLED(CONFIG_MODULES)\n"
          "\tANDROID_KABI_USE(2, struct module *sk_owner);\n"
          "#else\n"
          "\tANDROID_KABI_RESERVE(2);\n"
          "#endif\n"
          "\tANDROID_KABI_RESERVE(3);\n"
          "\tANDROID_KABI_RESERVE(4);\n"
          "\tANDROID_KABI_RESERVE(5);\n"
          "\tANDROID_KABI_RESERVE(6);\n"
          "\tANDROID_KABI_RESERVE(7);\n"
          "\tANDROID_KABI_RESERVE(8);\n"),
    ],

    # --- bpf core: pakai owner field upstream, aux tetap untuk vendor ---
    "kernel/bpf/core.c": [
        R("array->aux->owner", "text",
          "\t\tarray->owner_prog_type = fp->type;\n"
          "\t\tarray->owner_jited = fp->jited;\n"
          "\t\tarray->owner_attach_type = fp->expected_attach_type;\n"
          "\n"
          "\t\treturn true;\n"
          "\t}\n"
          "\n"
          "\treturn array->owner_prog_type == fp->type &&\n"
          "\t       array->owner_jited == fp->jited &&\n"
          "\t       array->owner_attach_type == fp->expected_attach_type;\n"),
    ],

    # --- local_storage: iterator upstream (nama field disesuaikan) ---
    "kernel/bpf/local_storage.c": [
        R("list_next_entry(storage, list_map)", "text",
          "\t\tstorage = list_next_entry(storage, list_map);\n"
          "\t\tif (list_entry_is_head(storage, &map->list, list_map))\n"),
    ],

    # --- sched: uclamp vendor + tipe return u64 upstream ---
    "kernel/sched/core.c": [
        R("uclamp_post_fork", "text",
          "void sched_post_fork(struct task_struct *p)\n"
          "{\n"
          "\tuclamp_post_fork(p);\n"
          "}\n"
          "\n"
          "u64 to_ratio(u64 period, u64 runtime)\n"),
    ],

    # --- schedutil: panggil helper ala CIP; isi helper disesuaikan di POST ---
    "kernel/sched/cpufreq_schedutil.c": [
        R("sugov_update_rate_limit_us(sg_policy);", "theirs"),
    ],

    # --- swapfile: lock inode vendor + validasi encrypted upstream ---
    "mm/swapfile.c": [
        R("IS_SWAPFILE(inode)", "text",
          "\tinode_lock(inode);\n"
          "\tif (IS_SWAPFILE(inode)) {\n"
          "\t\terror = -EBUSY;\n"
          "\t\tgoto bad_swap_unlock_inode;\n"
          "\t}\n"
          "\tif (IS_ENCRYPTED(inode)) {\n"
          "\t\tpr_warn_once(\n"
          "\t\t\t\"Filesystem-level encrypted swapfile '%s' is unsupported. Create a loop device over it, or use dm-crypt\\n\",\n"
          "\t\t\tname->name);\n"
          "\t\terror = -EINVAL;\n"
          "\t\tgoto bad_swap_unlock_inode;\n"
          "\t}\n"
          "\n"),
    ],

    # --- filter.c: versi upstream (switch-based) paling konsisten ---
    "net/core/filter.c": [
        R("sizeof_field(OBJ, OBJ_FIELD)", "theirs"),
        R("SOCK_OPS_GET_SK()", "theirs"),
    ],

    # --- ALSA: hitung wait time upstream; MTK 2 ms terlalu pendek ---
    "sound/core/pcm_lib.c": [
        R("Modified by MTK", "theirs"),
    ],

    # --- KVM arm64: topup di luar mmap_sem + baca seq di dalam ---
    "virt/kvm/arm/mmu.c": [
        R("mmap_read_unlock(current->mm);", "theirs"),
    ],
}


def render(kind, ours, theirs, value):
    if kind == "ours":
        return ours
    if kind == "theirs":
        return theirs
    if kind == "both":
        return ours.rstrip("\n") + "\n\n" + theirs.lstrip("\n")
    if kind == "text":
        return value
    raise ValueError("unknown action: " + str(kind))


def main():
    errors = []
    for path, rules in RULES.items():
        p = ROOT / path
        if not p.is_file():
            errors.append("MISSING FILE: " + path)
            continue
        src = p.read_text()
        matches = list(PAT.finditer(src))
        if not matches:
            print("SKIP (no markers): " + path)
            continue

        used = set()
        pieces = []
        pos = 0
        for m in matches:
            ours, theirs = m.group(1), m.group(2)
            hay = ours + theirs
            pick = None
            for idx, (needle, kind, value) in enumerate(rules):
                if needle in hay:
                    pick = (idx, kind, value)
                    break
            if pick is None:
                errors.append(
                    "UNHANDLED BLOCK in %s:\n%s" % (path, m.group(0)[:600])
                )
                continue
            idx, kind, value = pick
            used.add(idx)
            pieces.append(src[pos:m.start()])
            pieces.append(render(kind, ours, theirs, value))
            pos = m.end()
        pieces.append(src[pos:])
        if not any("UNHANDLED BLOCK in " + path in e for e in errors):
            p.write_text("".join(pieces))
        unused = [rules[i][0] for i in range(len(rules)) if i not in used]
        print("OK %s: %d block(s)%s" % (
            path, len(matches),
            " [rule unused: %s]" % ", ".join(unused) if unused else "",
        ))

    # Perbaikan di luar blok konflik yang wajib ikut berubah.
    post = {
        "kernel/sched/sched.h": [
            ("unsigned long to_ratio(", "u64 to_ratio("),
        ],
        "drivers/net/ethernet/stmicro/stmmac/ring_mode.c": [
            ("static void refill_desc3(void *priv_ptr, struct dma_desc *p)",
             "static void refill_desc3(struct stmmac_rx_queue *rx_q, struct dma_desc *p)"),
        ],
        # schedutil: pakai field vendor/MediaTek, bukan nama CIP murni
        "kernel/sched/cpufreq_schedutil.c": [
            ("freq_update_delay_ns", "up_rate_delay_ns"),
            ("tunables->rate_limit_us", "tunables->up_rate_limit_us"),
        ],
        # bpf_trace: static inline + varargs ditolak toolchain gcc-12
        "kernel/trace/bpf_trace.c": [
            ("static inline __printf(1, 0) int bpf_do_trace_printk(",
             "static __printf(1, 0) int bpf_do_trace_printk("),
        ],
        # blk-crypto: CIP menyisakan deklarasi inline tanpa body
        "include/linux/keyslot-manager.h": [
            ("inline void ksm_", "void ksm_"),
            ("inline int ksm_", "int ksm_"),
        ],
        "include/linux/blk-crypto.h": [
            ("inline void blk_crypto_flock(struct keyslot_manager *ksm, "
             "unsigned int flags);",
             "void blk_crypto_flock(struct keyslot_manager *ksm, "
             "unsigned int flags);"),
        ],
        # richtek: offset adalah ptrdiff_t, bukan int
        "sound/soc/codecs/richtek_spm_cls.c": [
            ('pr_info("%s: %d\\n", __func__, offset);',
             'pr_info("%s: %ld\\n", __func__, (long)offset);'),
            ('dev_info(dev, "%s: %d\\n", __func__, offset);',
             'dev_info(dev, "%s: %ld\\n", __func__, (long)offset);'),
        ],
        # mtk-usip: arg adalah unsigned long, bukan unsigned int
        "sound/soc/mediatek/common/mtk-usip.c": [
            ('Fail copy CALL_ENH_CONFIG from user Ptr: %x',
             'Fail copy CALL_ENH_CONFIG from user Ptr: %lx'),
            ('memory_size = %ld addr_phy = 0x%llx',
             'memory_size = %zu addr_phy = 0x%llx'),
        ],
        # btcvsd: irq status dibaca ke u32, bukan unsigned long
        "sound/soc/mediatek/common/mtk-btcvsd.c": [
            ("bt_reg_ctl = 0x%lx", "bt_reg_ctl = 0x%x"),
        ],
        # mtk-vcu: tmp->pa adalah unsigned long; cook/va adalah void *
        "drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c": [
            ("Free cmdq pa %llx ref_cnt = %d",
             "Free cmdq pa %lx ref_cnt = %d"),
            ("iova = %llx va = %llx va_id = %lld",
             "iova = %llx va = %p va_id = %lld"),
            ("Free buff = %d iova = %llx va = %llx va_id = %llx",
             "Free buff = %d iova = %llx va = %p va_id = %llx"),
        ],
        # mtk-vcodec: sgt adalah struct sg_table *; satu format kehilangan arg
        "drivers/media/platform/mtk-vcodec/mtk_vcodec_dec.c": [
            ('mtk_v4l2_err("dma_buf_map_attachment fail %d.\\n", sgt);',
             'mtk_v4l2_err("dma_buf_map_attachment fail %p.\\n", sgt);'),
            ('mtk_v4l2_err("[%d]Error!!src_buf is NULL!");',
             'mtk_v4l2_err("Error!!src_buf is NULL!");'),
        ],
        "drivers/media/platform/mtk-vcodec/mtk_vcodec_enc.c": [
            ('mtk_v4l2_err("dma_buf_map_attachment fail %d.\\n", sgt);',
             'mtk_v4l2_err("dma_buf_map_attachment fail %p.\\n", sgt);'),
        ],
        # -Werror=memset-elt-size: ARRAY_SIZE() menghitung elemen, bukan byte.
        # Baris 523 juga salah sasaran (count_ack), jadi pakai sizeof(max_load).
        "drivers/misc/mediatek/base/power/cm_mgr_v1/mtk_cm_mgr.c": [
            ("memset(count_ack, 0, ARRAY_SIZE(count_ack));",
             "memset(count_ack, 0, sizeof(count_ack));"),
            ("memset(max_load, 0, ARRAY_SIZE(count_ack));",
             "memset(max_load, 0, sizeof(max_load));"),
        ],
        # pbm: format [%s] butuh __func__; arg kedua adalah volt (bukan string)
        "drivers/misc/mediatek/base/power/pbm_v4/mtk_pbm.c": [
            ('pr_notice_ratelimited("[%s] wrong volt=%d, set 4V\\n",\n\t\t\tbat_vol);',
             'pr_notice_ratelimited("[%s] wrong volt=%d, set 4V\\n",\n\t\t\t__func__, bat_vol);'),
        ],
        # camera_dpe: dua LOG_INF setelah if tanpa brace diindentasi 2 tab,
        # seolah ikut terlindungi. Turunkan 1 tab (perilaku sama, warning hilang).
        "drivers/misc/mediatek/cameraisp/dpe/mt6768/camera_dpe.c": [
            ('\t\tLOG_INF("DVE:bFound:%d, DveWriteIdx:%d, WriteIdx:%d\\n",',
             '\tLOG_INF("DVE:bFound:%d, DveWriteIdx:%d, WriteIdx:%d\\n",'),
            ('\t\tLOG_INF("DVE:gDveCnt:%d,RequestState:%d,HWIdx:%d\\n",',
             '\tLOG_INF("DVE:gDveCnt:%d,RequestState:%d,HWIdx:%d\\n",'),
        ],
    }
    for path, subs in post.items():
        p = ROOT / path
        if not p.is_file():
            continue
        s = p.read_text()
        old = s
        for a, b in subs:
            s = s.replace(a, b)
        if s != old:
            p.write_text(s)
            print("POST-FIX: " + path)

    # f2fs_msg(sb, level, ...) tidak ada di vendor tree. CIP menyisipkannya di
    # file non-konflik juga (mis. checkpoint.c), jadi sweep semua file f2fs.
    f2fs_msg_subs = [
        ("f2fs_msg(sbi->sb, KERN_ERR,", "f2fs_err(sbi,"),
        ("f2fs_msg(sbi->sb, KERN_WARNING,", "f2fs_err(sbi,"),
        ("f2fs_msg(sbi->sb, KERN_NOTICE,", "f2fs_err(sbi,"),
        ("f2fs_msg(sbi->sb, KERN_INFO,", "f2fs_err(sbi,"),
        ("f2fs_msg(sbi->sb, KERN_DEBUG,", "f2fs_err(sbi,"),
        ("f2fs_msg(sb, KERN_ERR,", "f2fs_err(F2FS_SB(sb),"),
        ("f2fs_msg(sb, KERN_WARNING,", "f2fs_err(F2FS_SB(sb),"),
        ("f2fs_msg(sb, KERN_NOTICE,", "f2fs_err(F2FS_SB(sb),"),
        ("f2fs_msg(sb, KERN_INFO,", "f2fs_err(F2FS_SB(sb),"),
        ("f2fs_msg(sb, KERN_DEBUG,", "f2fs_err(F2FS_SB(sb),"),
    ]
    for p in sorted((ROOT / "fs/f2fs").glob("*.[ch]")):
        s = p.read_text()
        old = s
        for a, b in f2fs_msg_subs:
            s = s.replace(a, b)
        if s != old:
            p.write_text(s)
            print("POST-FIX: %s (f2fs_msg)" % p.relative_to(ROOT))

    # chipone touch: source memakai 4 spasi untuk if/cts_err tetapi satu tab
    # untuk return ret, sehingga -Werror=misleading-indentation mengeluh.
    # Samakan ke tab (read_text/write_text juga menormalkan CRLF -> LF).
    p = ROOT / "drivers/input/touchscreen/mediatek/chipone_ICNL_9916/cts_core.c"
    if p.is_file():
        s = p.read_text()
        old = ('    if (ret)\n'
               '        cts_err("Send CMD_CHARGER_%s failed %d", attached ? "ATTACHED" : "DETACHED", ret);\n'
               '\n'
               '\treturn ret;')
        new = ('\tif (ret)\n'
               '\t\tcts_err("Send CMD_CHARGER_%s failed %d", attached ? "ATTACHED" : "DETACHED", ret);\n'
               '\n'
               '\treturn ret;')
        if old in s:
            p.write_text(s.replace(old, new, 1))
            print("POST-FIX: cts_core.c indentation")
        elif '\tif (ret)\n\t\tcts_err("Send CMD_CHARGER_' not in s:
            print("WARN: cts_core.c indentation pattern not found")

    # CIP memanggil sugov_update_rate_limit_us(); pastikan helper ada dan
    # memakai field vendor supaya tidak missing struct member saat build.
    p = ROOT / "kernel/sched/cpufreq_schedutil.c"
    if p.is_file():
        s = p.read_text()
        if ("sugov_update_rate_limit_us(" in s and
                "void sugov_update_rate_limit_us(" not in s):
            anchor = "static void sugov_update_single("
            helper = (
                "static inline void sugov_update_rate_limit_us("
                "struct sugov_policy *sg_policy)\n"
                "{\n"
                "\tsg_policy->up_rate_delay_ns =\n"
                "\t\tsg_policy->tunables->up_rate_limit_us * NSEC_PER_USEC;\n"
                "\tupdate_min_rate_limit_ns(sg_policy);\n"
                "}\n\n"
            )
            if anchor in s:
                p.write_text(s.replace(anchor, helper + anchor, 1))
                print("POST-FIX: sugov_update_rate_limit_us helper")

    # filter.c: HEAD menyimpan case vendor (SOCK_OPS_GET_TCP_SOCK_FIELD /
    # SOCK_OPS_GET_SK) di LUAR blok konflik. CIP menghapus macro itu, jadi
    # resolver per-blok tidak cukup. Ambil seluruh fungsi dari CIP, lalu
    # tambahkan kembali hanya case vendor yang memang tidak ada di CIP.
    p = ROOT / "net/core/filter.c"
    if p.is_file():
        s = p.read_text()
        try:
            cip_src = subprocess.check_output(
                ["git", "-C", str(ROOT), "show",
                 "refs/remotes/cip/cip-target:net/core/filter.c"],
                text=True)
            ca = cip_src.index("static u32 sock_ops_convert_ctx_access(")
            cb = cip_src.index("\nstatic u32 sk_skb_convert_ctx_access(", ca)
            fn = cip_src[ca:cb]

            head_src = subprocess.check_output(
                ["git", "-C", str(ROOT), "show", "HEAD:net/core/filter.c"],
                text=True)

            # CIP menyamakan sizeof(bpf_sock_ops.op) dengan kern.op, tetapi
            # vendor memakai u8 di kern (UAPI u32). Ambil case op/reply dari
            # HEAD supaya BUILD_BUG_ON tidak gagal dan offset tetap benar.
            cip_op = (
                "\tcase offsetof(struct bpf_sock_ops, op) ...\n"
                "\t     offsetof(struct bpf_sock_ops, replylong[3]):\n"
                "\t\tBUILD_BUG_ON(FIELD_SIZEOF(struct bpf_sock_ops, op) !=\n"
                "\t\t\t     FIELD_SIZEOF(struct bpf_sock_ops_kern, op));\n"
                "\t\tBUILD_BUG_ON(FIELD_SIZEOF(struct bpf_sock_ops, reply) !=\n"
                "\t\t\t     FIELD_SIZEOF(struct bpf_sock_ops_kern, reply));\n"
                "\t\tBUILD_BUG_ON(FIELD_SIZEOF(struct bpf_sock_ops, replylong) !=\n"
                "\t\t\t     FIELD_SIZEOF(struct bpf_sock_ops_kern, replylong));\n"
                "\t\toff = si->off;\n"
                "\t\toff -= offsetof(struct bpf_sock_ops, op);\n"
                "\t\toff += offsetof(struct bpf_sock_ops_kern, op);\n"
                "\t\tif (type == BPF_WRITE)\n"
                "\t\t\t*insn++ = BPF_STX_MEM(BPF_W, si->dst_reg, si->src_reg,\n"
                "\t\t\t\t\t      off);\n"
                "\t\telse\n"
                "\t\t\t*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,\n"
                "\t\t\t\t\t      off);\n"
                "\t\tbreak;\n\n"
            )
            ha = head_src.index("\tcase offsetof(struct bpf_sock_ops, op):")
            hb = head_src.index("\tcase offsetof(struct bpf_sock_ops, family):", ha)
            if cip_op in fn:
                fn = fn.replace(cip_op, head_src[ha:hb], 1)

            # Makro vendor menyelamatkan R9/register lain saat dst == src;
            # makro CIP menghapusnya. Kembalikan versi vendor.
            def macro_of(head, start, end):
                a = head.index(start)
                return head[a:head.index(end, a)]

            head_get = macro_of(head_src, "#define SOCK_OPS_GET_FIELD(",
                                "\n#define SOCK_OPS_GET_SK()")
            head_sk = macro_of(head_src, "#define SOCK_OPS_GET_SK()",
                               "\n#define SOCK_OPS_GET_TCP_SOCK_FIELD(")
            head_set = macro_of(head_src, "#define SOCK_OPS_SET_FIELD(",
                                "\n#define SOCK_OPS_GET_OR_SET_FIELD(")

            ga = fn.index("#define SOCK_OPS_GET_FIELD(")
            gb = fn.index("\n\n\tswitch (si->off) {", ga)
            fn = fn[:ga] + "#undef SOCK_OPS_GET_FIELD\n" + head_get + fn[gb:]

            sa = fn.index("#define SOCK_OPS_SET_FIELD(")
            sb = fn.index("\n\n#define SOCK_OPS_GET_OR_SET_FIELD(", sa)
            fn = fn[:sa] + "#undef SOCK_OPS_SET_FIELD\n" + head_set + fn[sb:]

            if "/* Helper macro for adding read access" in fn:
                fn = fn.replace("/* Helper macro for adding read access",
                                head_sk + "/* Helper macro for adding read access", 1)

            vendor_cases = (
                "\tcase offsetof(struct bpf_sock_ops, sk):\n"
                "\t\tSOCK_OPS_GET_SK();\n"
                "\t\tbreak;\n"
                "\tcase offsetof(struct bpf_sock_ops, skb_data_end):\n"
                "\t\t*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_sock_ops_kern,\n"
                "\t\t\t\t\t\t       skb_data_end),\n"
                "\t\t\t\t\t      si->dst_reg, si->src_reg,\n"
                "\t\t\t\t\t      offsetof(struct bpf_sock_ops_kern,\n"
                "\t\t\t\t\t\t       skb_data_end));\n"
                "\t\tbreak;\n"
                "\tcase offsetof(struct bpf_sock_ops, skb_data):\n"
                "\t\t*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_sock_ops_kern,\n"
                "\t\t\t\t\t\t       skb),\n"
                "\t\t\t\t\t      si->dst_reg, si->src_reg,\n"
                "\t\t\t\t\t      offsetof(struct bpf_sock_ops_kern, skb));\n"
                "\t\t*insn++ = BPF_JMP_IMM(BPF_JEQ, si->dst_reg, 0, 1);\n"
                "\t\t*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, data),\n"
                "\t\t\t\t\t      si->dst_reg, si->dst_reg,\n"
                "\t\t\t\t\t      offsetof(struct sk_buff, data));\n"
                "\t\tbreak;\n"
                "\tcase offsetof(struct bpf_sock_ops, skb_len):\n"
                "\t\t*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_sock_ops_kern,\n"
                "\t\t\t\t\t\t       skb),\n"
                "\t\t\t\t\t      si->dst_reg, si->src_reg,\n"
                "\t\t\t\t\t      offsetof(struct bpf_sock_ops_kern, skb));\n"
                "\t\t*insn++ = BPF_JMP_IMM(BPF_JEQ, si->dst_reg, 0, 1);\n"
                "\t\t*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, len),\n"
                "\t\t\t\t\t      si->dst_reg, si->dst_reg,\n"
                "\t\t\t\t\t      offsetof(struct sk_buff, len));\n"
                "\t\tbreak;\n"
                "\tcase offsetof(struct bpf_sock_ops, skb_tcp_flags):\n"
                "\t\toff = offsetof(struct sk_buff, cb);\n"
                "\t\toff += offsetof(struct tcp_skb_cb, tcp_flags);\n"
                "\t\t*target_size = FIELD_SIZEOF(struct tcp_skb_cb, tcp_flags);\n"
                "\t\t*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_sock_ops_kern,\n"
                "\t\t\t\t\t\t       skb),\n"
                "\t\t\t\t\t      si->dst_reg, si->src_reg,\n"
                "\t\t\t\t\t      offsetof(struct bpf_sock_ops_kern, skb));\n"
                "\t\t*insn++ = BPF_JMP_IMM(BPF_JEQ, si->dst_reg, 0, 1);\n"
                "\t\t*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct tcp_skb_cb,\n"
                "\t\t\t\t\t\t       tcp_flags),\n"
                "\t\t\t\t\t      si->dst_reg, si->dst_reg, off);\n"
                "\t\tbreak;\n"
            )
            tail = "\n\t}\n\treturn insn - insn_buf;\n}"
            if tail in fn:
                fn = fn.replace(tail, "\n" + vendor_cases + tail, 1)

            ma = s.index("static u32 sock_ops_convert_ctx_access(")
            mb = s.index("\nstatic u32 sk_skb_convert_ctx_access(", ma)
            p.write_text(s[:ma] + fn + s[mb:])
            print("POST-FIX: net/core/filter.c (sock_ops from CIP + vendor cases)")
        except (subprocess.CalledProcessError, ValueError) as exc:
            errors.append("filter.c CIP function replacement failed: " + str(exc))

    if errors:
        print("\n=== TIDAK SEPENUHNYA BERHASIL ===", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)
    print("\nSelesai. Cek: grep -R -n '^<<<<<<<\\|^=======\\|^>>>>>>>' .")


if __name__ == "__main__":
    main()
