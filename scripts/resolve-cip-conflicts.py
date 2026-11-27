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
        # richtek: offset adalah ptrdiff_t, bukan int
        "sound/soc/codecs/richtek_spm_cls.c": [
            ('pr_info("%s: %d\\n", __func__, offset);',
             'pr_info("%s: %ld\\n", __func__, (long)offset);'),
            ('dev_info(dev, "%s: %d\\n", __func__, offset);',
             'dev_info(dev, "%s: %ld\\n", __func__, (long)offset);'),
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

    # chipone touch: return ret tidak sengaja ter-indent di dalam if.
    p = ROOT / "drivers/input/touchscreen/mediatek/chipone_ICNL_9916/cts_core.c"
    if p.is_file():
        s = p.read_text()
        marker = "cts_set_dev_charger_attached"
        idx = s.find(marker)
        if idx >= 0:
            tail = s[idx:]
            lines = tail.splitlines(True)
            fixed = False
            for i in range(len(lines) - 1):
                if lines[i].strip() == "if (ret)":
                    for j in range(i + 1, min(i + 6, len(lines))):
                        if (lines[j].strip() == "return ret;" and
                                lines[j].startswith("\t\t")):
                            lines[j] = lines[j][1:]
                            fixed = True
                            break
                    if fixed:
                        break
            if fixed:
                p.write_text(s[:idx] + "".join(lines))
                print("POST-FIX: cts_core.c indentation")

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

    if errors:
        print("\n=== TIDAK SEPENUHNYA BERHASIL ===", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)
    print("\nSelesai. Cek: grep -R -n '^<<<<<<<\\|^=======\\|^>>>>>>>' .")


if __name__ == "__main__":
    main()
