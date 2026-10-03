# -*- coding: utf-8 -*-
"""V4.1_808 构建脚本：768 基线 + 全部历史 dex 修复 + V808 音乐播放时长(html)。

构建口径（沿用 760/768 系列）：
  原始 AXML 编码 + 按原版压缩 + zipalign + 官方 apksigner v1/v2/v3 签名。

本版改动：
  1) 替换 assets/dashboard.html 为 V808 页面（新增后台音乐「播放时长」设置）；
  2) 替换 classes.dex 为含历史修复的 classes_new.dex；
  3) AndroidManifest.xml 原地升版本号 768 -> 808（等长，不动字符串池）。

--------------------------------------------------------------------------
用法：
  python rebuild_808.py [--src <基线APK>] [--html <V808 HTML>] [--dex <classes_new.dex>]
                        [--out <输出APK>] [--ks <密钥库>] [--alias <别名>] [--passwd <口令>]

默认路径以仓库根目录为基准（脚本所在目录的上一级），可用参数覆盖。
密钥库口令不写在脚本里：从环境变量 KD_PASS 读取（亦可用 --passwd 显式传入）。
依赖：python3、zipalign、apksigner.jar、java。
--------------------------------------------------------------------------
"""
import os
import sys
import struct
import zlib
import zipfile
import hashlib
import argparse
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, os.pardir))


def deflate(data):
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def write_apk(path, items, compress_names):
    """按原版口径写 APK：对齐 4 字节、指定条目使用 deflate、其余 store。"""
    ALIGN = 4
    buf = bytearray()
    central = []
    for nm, data in items:
        name_b = nm.encode("utf-8")
        if nm in compress_names:
            body = deflate(data)
            meth = 8
        else:
            body = data
            meth = 0
        crc = zlib.crc32(data) & 0xffffffff
        flag = 0x0800
        lho = len(buf)
        base = lho + 30 + len(name_b)
        extra_len = (ALIGN - (base % ALIGN)) % ALIGN if meth == 0 else 0
        extra = b"\x00" * extra_len
        buf += struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, flag, meth, 0, 0, crc,
                           len(body), len(data), len(name_b), len(extra))
        buf += name_b + extra + body
        central.append(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, flag, meth, 0, 0, crc,
                                   len(body), len(data), len(name_b), len(extra), 0, 0, 0, 0, lho)
                       + name_b + extra)
    cd_start = len(buf)
    for c in central:
        buf += c
    cd_size = len(buf) - cd_start
    buf += struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(items), len(items), cd_size, cd_start, 0)
    with open(path, "wb") as f:
        f.write(buf)


def bump_version_code(manifest_bytes, old_code, new_code):
    """原地改写 versionCode（typed value，等长 4 字节），不动字符串池。"""
    old_le = struct.pack("<I", old_code)
    new_le = struct.pack("<I", new_code)
    idx = manifest_bytes.find(b"\x08\x00\x00\x10" + old_le)
    if idx < 0:
        idx = manifest_bytes.find(b"\x08\x00\x10\x00" + old_le)
    if idx < 0:
        raise RuntimeError("在 AndroidManifest.xml 中找不到 versionCode typed-value (%d)" % old_code)
    data_off = idx + 4
    out = bytearray(manifest_bytes)
    out[data_off:data_off + 4] = new_le
    print("  versionCode patched %d -> %d at offset %d" % (old_code, new_code, data_off))
    return bytes(out)


COMPRESS = {"assets/dashboard.html", "assets/hls.min.js", "assets/radio_presets.js",
            "AndroidManifest.xml", "classes.dex",
            "res/drawable-xxhdpi/ic_launcher.png", "res/drawable/ic_notify.xml",
            "res/xml/device_admin.xml", "res/xml/network_security_config.xml"}


def main():
    ap = argparse.ArgumentParser(description="构建 KDashBoardL V4.1_808")
    ap.add_argument("--src", default=os.path.join(ROOT, "KDashBoardL_V4.0_768.apk"),
                    help="基线 APK（含历史 dex 与 768 清单）")
    ap.add_argument("--html", default=os.path.join(ROOT, "src", "assets", "dashboard.html"),
                    help="V808 页面 HTML")
    ap.add_argument("--dex", default=os.path.join(ROOT, "src", "classes_new.dex"),
                    help="含历史修复的 classes_new.dex（省略则保留基线 dex）")
    ap.add_argument("--out", default=os.path.join(ROOT, "KDashBoardL_V4.1_808.apk"),
                    help="输出 APK 路径")
    ap.add_argument("--ks", default=os.environ.get("KD_KS", os.path.join(ROOT, "tools", "kd_keystore.p12")),
                    help="签名密钥库（PKCS12），默认读环境变量 KD_KS")
    ap.add_argument("--alias", default=os.environ.get("KD_ALIAS", "KDashBoardL"), help="密钥别名，默认读 KD_ALIAS")
    ap.add_argument("--passwd", default=os.environ.get("KD_PASS", ""),
                    help="密钥库/密钥口令，默认读环境变量 KD_PASS（勿写入命令行历史）")
    ap.add_argument("--old-code", type=int, default=768, help="基线 versionCode")
    ap.add_argument("--new-code", type=int, default=808, help="目标 versionCode")
    ap.add_argument("--min-sdk", default="14", help="apksigner --min-sdk-version")
    ap.add_argument("--zipalign", default=os.environ.get("ZIPALIGN", "zipalign"),
                    help="zipalign 可执行文件")
    ap.add_argument("--apksigner", default=os.environ.get("APKSIGNER", "apksigner.jar"),
                    help="apksigner.jar 路径")
    ap.add_argument("--java", default=os.environ.get("JAVA", "java"),
                    help="java 可执行文件")
    args = ap.parse_args()

    work = os.path.join(ROOT, "_build", "v%d" % args.new_code)
    os.makedirs(work, exist_ok=True)
    unsigned = os.path.join(work, "u%d.apk" % args.new_code)
    aligned = os.path.join(work, "a%d.apk" % args.new_code)

    src = zipfile.ZipFile(args.src)
    entries = [(zi.filename, src.read(zi.filename)) for zi in src.infolist()
               if not zi.filename.startswith("META-INF/") and not zi.filename.endswith(".bak")]
    h_old = dict(entries)["assets/dashboard.html"]
    m_old = dict(entries)["AndroidManifest.xml"]
    h_new = open(args.html, "rb").read()

    print("src html sha:", hashlib.sha256(h_old).hexdigest()[:16], len(h_old))
    print("new html sha:", hashlib.sha256(h_new).hexdigest()[:16], len(h_new))

    d_new = None
    if args.dex and os.path.exists(args.dex):
        d_old = dict(entries).get("classes.dex")
        d_new = open(args.dex, "rb").read()
        print("src dex  sha:", hashlib.sha256(d_old).hexdigest()[:16] if d_old else "-", len(d_old) if d_old else 0)
        print("new dex  sha:", hashlib.sha256(d_new).hexdigest()[:16], len(d_new))

    m_new = bump_version_code(m_old, args.old_code, args.new_code)

    out_entries = []
    for (n, d) in entries:
        if n == "assets/dashboard.html":
            out_entries.append((n, h_new))
        elif n == "classes.dex" and d_new is not None:
            out_entries.append((n, d_new))
        elif n == "AndroidManifest.xml":
            out_entries.append((n, m_new))
        else:
            out_entries.append((n, d))
    out_entries.sort(key=lambda e: e[0])

    write_apk(unsigned, out_entries, COMPRESS)
    print("unsigned:", os.path.getsize(unsigned))

    if os.path.exists(aligned):
        os.remove(aligned)
    r = subprocess.run([args.zipalign, "-f", "-p", "4", unsigned, aligned],
                       capture_output=True, text=True)
    print("zipalign rc=%d %s" % (r.returncode, r.stderr[:200]))

    out = args.out
    if os.path.exists(out):
        os.remove(out)
    r = subprocess.run([args.java, "-jar", args.apksigner, "sign",
                        "--ks", args.ks, "--ks-key-alias", args.alias,
                        "--ks-pass", "pass:" + args.passwd, "--key-pass", "pass:" + args.passwd,
                        "--min-sdk-version", args.min_sdk,
                        "--v1-signing-enabled", "true",
                        "--v2-signing-enabled", "true",
                        "--v3-signing-enabled", "true",
                        "--out", out, aligned], capture_output=True, text=True)
    print("sign rc=%d %s %s" % (r.returncode, r.stdout[:150], r.stderr[:150]))
    r = subprocess.run([args.java, "-jar", args.apksigner, "verify", "--verbose",
                        "--min-sdk-version", args.min_sdk, out], capture_output=True, text=True)
    print("verify ->", "Verifies" if "Verifies" in r.stdout else "FAILED")

    print("=== self-check ===")
    z = zipfile.ZipFile(out)
    same_ht = z.read("assets/dashboard.html") == h_new
    m_out = z.read("AndroidManifest.xml")
    vc_out = struct.unpack_from("<I", m_out, m_out.find(b"\x08\x00\x00\x10") + 4)[0]
    print("  html  == 新 HTML          :", same_ht)
    print("  manifest versionCode      :", vc_out)
    others_ok = True
    for zi in src.infolist():
        n = zi.filename
        if n.startswith("META-INF/") or n.endswith(".bak") or n in (
                "assets/dashboard.html", "classes.dex", "AndroidManifest.xml"):
            continue
        if z.read(n) != src.read(n):
            others_ok = False
            print("  DIFF:", n)
    print("  其余条目与基线一致        :", others_ok)
    ok = same_ht and others_ok and vc_out == args.new_code
    print("  ", "OK（html 已替换 + versionCode=%d）" % args.new_code if ok else "MISMATCH")
    print("FINAL:", out, os.path.getsize(out) if os.path.exists(out) else "MISSING")


if __name__ == "__main__":
    main()
