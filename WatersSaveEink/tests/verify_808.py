# -*- coding: utf-8 -*-
"""V4.1_808 独立复检：ZIP 结构 / AXML 版本 / 包内 dashboard.html 指纹 / zipalign / apksigner 签名。

--------------------------------------------------------------------------
用法：
  python verify_808.py [APK ...]

不传参数时，默认校验仓库 dist/ 下的两个 APK：
  dist/KDashBoardL_V3.3_760.apk        （V1，Android 4.0 专用）
  dist/KDashBoardL_V4.1_808_v123.apk   （808，全签名）

环境变量（可选）：
  JAVA / ZIPALIGN / APKSIGNER  —— 指定对应工具路径；未设置时使用 PATH 中的命令。
--------------------------------------------------------------------------
"""
import os
import sys
import struct
import zipfile
import hashlib
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, os.pardir))
DIST = os.path.join(ROOT, "dist")

JAVA = os.environ.get("JAVA", "java")
ZIPALIGN = os.environ.get("ZIPALIGN", "zipalign")
APKSIGNER = os.environ.get("APKSIGNER", "apksigner.jar")

APKS = [os.path.join(DIST, "KDashBoardL_V3.3_760.apk"),
        os.path.join(DIST, "KDashBoardL_V4.1_808_v123.apk")]
if len(sys.argv) > 1:
    APKS = [p if os.path.isabs(p) else os.path.join(ROOT, p) for p in sys.argv[1:]]

out = []


def log(s=""):
    print(s)
    out.append(s)


def read_axml_version(data):
    """从 AndroidManifest.xml(AXML) 中取 versionCode / versionName（简化解析）。"""
    if len(data) < 8:
        return {}
    off = 8
    sp_type, sp_hdr, sp_size = struct.unpack("<HHI", data[off:off + 8])
    strcount, stylecount, flags, strstart, stylestart = struct.unpack("<IIIII", data[off + 8:off + 28])
    utf8 = bool(flags & (1 << 8))
    offsets = struct.unpack("<%dI" % strcount, data[off + 28:off + 28 + 4 * strcount])
    base = off + strstart

    def getstr(i):
        o = base + offsets[i]
        if utf8:
            p = o
            n = data[p]
            p += 1
            if n & 0x80:
                p += 1
            n2 = data[p]
            p += 1
            if n2 & 0x80:
                p += 1
            end = data.index(b"\x00", p)
            return data[p:end].decode("utf-8", "replace")
        n = struct.unpack("<H", data[o:o + 2])[0]
        return data[o + 2:o + 2 + n * 2].decode("utf-16-le", "replace")

    strings = [getstr(i) for i in range(strcount)]
    res = {}
    p = off + sp_size
    while p < len(data) - 8:
        ctype, chdr, csize = struct.unpack("<HHI", data[p:p + 8])
        if ctype == 0x0180:
            p += csize
            continue
        if ctype == 0x0102:
            attr_start, attr_size, attr_count = struct.unpack("<HHH", data[p + 24:p + 30])
            astart = p + 16 + attr_start
            for k in range(attr_count):
                a = astart + k * attr_size
                ns_i, name_i, rawv_i = struct.unpack("<iii", data[a:a + 12])
                vsize, vres0, vtype, vdata = struct.unpack("<HBBI", data[a + 12:a + 20])
                aname = strings[name_i] if 0 <= name_i < len(strings) else "?"
                if aname == "versionCode" and vtype == 0x10:
                    res["versionCode"] = vdata
                elif aname == "versionName" and vtype == 0x03:
                    res["versionName"] = strings[vdata] if vdata < len(strings) else "?"
            break
        p += csize
    return res


for apk in APKS:
    log("=" * 68)
    if not os.path.exists(apk):
        log("[缺失] %s" % apk)
        continue
    size = os.path.getsize(apk)
    log("[APK] %s" % apk)
    log("      大小 %d 字节  sha256 %s" % (size, hashlib.sha256(open(apk, "rb").read()).hexdigest()[:16]))
    try:
        z = zipfile.ZipFile(apk)
    except Exception as e:
        log("  ZIP 打开失败: %s" % e)
        continue
    bad = z.testzip()
    log("  ZIP 结构完整性      : %s" % ("OK" if bad is None else "损坏条目 %s" % bad))
    names = z.namelist()
    log("  条目数              : %d" % len(names))
    if "AndroidManifest.xml" in names:
        m = z.read("AndroidManifest.xml")
        log("  AXML 版本           : %s" % read_axml_version(m))
    if "assets/dashboard.html" in names:
        h = z.read("assets/dashboard.html")
        log("  包内 dashboard.html : %d 字节  sha256 %s" % (len(h), hashlib.sha256(h).hexdigest()[:16]))
    if "classes.dex" in names:
        d = z.read("classes.dex")
        checks = {s: (s.encode() in d) for s in
                  ["sAlive", "sAfListener", "requestNotify", "openAppDetails", "getBattery", "POST_NOTIFICATIONS"]}
        log("  dex 关键字          : %s" % checks)
    # zipalign 校验
    r = subprocess.run([ZIPALIGN, "-c", "-v", "4", apk], capture_output=True, text=True)
    log("  zipalign -c 4       : %s" % ("OK" if r.returncode == 0 else "FAIL rc=%d %s" % (r.returncode, r.stderr[:100])))
    # 签名校验
    r = subprocess.run([JAVA, "-jar", APKSIGNER, "verify", "--verbose",
                        "--min-sdk-version", "14", apk], capture_output=True, text=True)
    txt = r.stdout
    schemes = [s for s in ("v1", "v2", "v3") if ("%s scheme" % s) in txt.lower()]
    log("  签名校验            : %s  方案=%s" % ("Verifies" if "Verifies" in txt else "FAILED", ",".join(schemes) or "-"))

log("=" * 68)
log("复检完成，共 %d 个 APK。" % len([p for p in APKS if os.path.exists(p)]))
