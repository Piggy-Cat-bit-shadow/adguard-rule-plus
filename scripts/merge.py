#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, time, urllib.request, gzip, hashlib

SRC_FILE = "sources.txt"
OUT_DIR = "dist"; os.makedirs(OUT_DIR, exist_ok=True)

# ---------- 正则 ----------
R_BLANK    = re.compile(r'^\s*$')
R_COMMENT  = re.compile(r'^\s*(?:!|#)(?!@#)')
R_COSMETIC = re.compile(r'^\s*(?:##|#@#)')
R_HOSTS    = re.compile(r'^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([A-Za-z0-9._-]+)\s*$')
R_DOMAIN   = re.compile(r'^\s*(?:\|\|)?([A-Za-z0-9._-]+\.[A-Za-z]{2,})(?:\^)?\s*$')
R_DNSREWRITE = re.compile(r'^\s*\|\|([A-Za-z0-9._-]+\.[A-Za-z]{2,})\^\$dnsrewrite=.*$')
R_DNSTYPE    = re.compile(r'^\s*\|\|([A-Za-z0-9._-]+\.[A-Za-z]{2,})\^\$dnstype=.*$')

def idna_norm(d:str)->str:
    try:
        return d.encode("idna").decode("ascii").lower().strip(".")
    except Exception:
        return d.lower().strip(".")

def fetch(url:str, timeout=60)->str:
    req = urllib.request.Request(url, headers={"User-Agent":"AGH-Merger/1.3"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        if r.getheader("Content-Encoding","").lower()=="gzip":
            data = gzip.decompress(data)
    return data.decode("utf-8", errors="ignore")

def normalize_and_dedupe(all_lines:list, keep_idna=True):
    raw_rules = set()       # 网络层规则（保留）
    total_before = 0
    excluded_dns_count = 0  # 被剔除的规则数量

    for raw in all_lines:
        total_before += 1
        s = raw.strip().replace("\ufeff","")
        if R_BLANK.match(s) or R_COMMENT.match(s) or R_COSMETIC.match(s):
            continue

        # 删除 AdGuardHome / DNS 层规则
        if R_HOSTS.match(s) or R_DOMAIN.match(s) or R_DNSREWRITE.match(s) or R_DNSTYPE.match(s):
            excluded_dns_count += 1
            continue

        # 保留网络层规则
        if s.startswith('@@') or s.startswith('||') or s.startswith('|') or ('$' in s) or (s.startswith('/') and s.endswith('/')):
            raw_rules.add(s)
            continue

    rules_sorted = sorted(raw_rules)
    total_after = len(rules_sorted)
    stats = {
        "total_before": total_before,
        "total_after": total_after,
        "dedup_removed": max(total_before - total_after, 0),
        "excluded_dns_count": excluded_dns_count,
    }
    return rules_sorted, stats

def header(title, sources):
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    h = [
        f"! {title}",
        f"! Generated at: {now}",
        f"! Sources:"
    ] + [f"!  - {s}" for s in sources] + [
        "! Notes:",
        "! - DNS/hosts rules removed for mobile use.",
        ""
    ]
    return "\n".join(h)

def write_mobile_output(mobile_rules, sources):
    with open(os.path.join(OUT_DIR, "merged_adblock_mobile.txt"), "w", encoding="utf-8") as f:
        f.write(header("Mobile-only Adblock list (no AGH/DNS rules)", sources))
        for r in mobile_rules:
            f.write(r + "\n")

def main():
    if not os.path.exists(SRC_FILE):
        raise SystemExit("sources.txt not found.")

    # 读取源
    sources = []
    with open(SRC_FILE,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith("#"):
                sources.append(u)

    # 拉取规则
    lines = []
    for url in sources:
        try:
            txt = fetch(url)
            lines.extend(txt.splitlines())
            print("OK:", url)
        except Exception as e:
            print("FAIL:", url, e)

    # 去重 & 删除 DNS 层规则
    mobile_rules, stats = normalize_and_dedupe(lines)

    # 写出手机端规则
    write_mobile_output(mobile_rules, sources)

    # 校验 + 日志
    p = os.path.join(OUT_DIR, "merged_adblock_mobile.txt")
    with open(p, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()[:16]
    print(f"Wrote {p}  sha256[:16]={sha}")

    print(f"总输入行: {stats['total_before']}")
    print(f"输出有效规则: {stats['total_after']}")
    print(f"去掉重复/无效: {stats['dedup_removed']}")
    print(f"剔除 AdGuard Home/DNS 层规则: {stats['excluded_dns_count']} 行")

if __name__ == "__main__":
    main()
