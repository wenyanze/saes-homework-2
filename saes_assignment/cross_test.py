"""Compare this Python implementation with the other group's C++ CLI.

Run from the project root:
python cross_test.py --peer-dir D:/cNew/s-aes-main/s-aes-main
No source files or executables in the peer directory are modified.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
import platform
import random
import re
import subprocess
import sys
from datetime import timezone, timedelta

PROJECT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT))
from saes import (  # noqa: E402
    ascii_encrypt, cbc_encrypt, decrypt_block, double_decrypt,
    double_encrypt, encrypt_block, triple_decrypt, triple_encrypt,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=PROJECT / "tests" / "cross-test")
    parser.add_argument("--seed", type=int, default=20261027)
    args = parser.parse_args()
    peer = args.peer_dir.resolve()
    executable = peer / "saes.exe"
    # Verify all inputs before running; hashes identify the exact local artifacts.
    files = [PROJECT / "saes.py", Path(__file__).resolve(), executable,
             peer / "src" / "saes.cpp", peer / "src" / "saes.h", peer / "src" / "main.cpp"]
    hashes = {str(path): digest(path) for path in files}
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    def call(*arguments: str) -> str:
        completed = subprocess.run([str(executable), *arguments], capture_output=True,
                                   check=True, timeout=15)
        return completed.stdout.decode("ascii").strip()

    def block_call(*arguments: str) -> int:
        value = call(*arguments)
        if not re.fullmatch(r"[0-9A-Fa-f]{4}", value):
            raise ValueError(f"unexpected peer output: {value!r}")
        return int(value, 16)

    rng = random.Random(args.seed)
    fixed = [(0xD728, 0x4AF5), (0, 0), (0xFFFF, 0xFFFF), (1, 1),
             (0x1234, 0xABCD), (0x80F0, 0x0F08)]
    samples = [("block", p, (k,)) for p, k in fixed]
    samples += [("block", rng.randrange(65536), (rng.randrange(65536),)) for _ in range(1000)]
    for mode, count in (("double", 2), ("eee", 3)):
        samples += [(mode, rng.randrange(65536), tuple(rng.randrange(65536) for _ in range(count)))
                    for _ in range(100)]
    rows = []
    for index, (mode, plaintext, keys) in enumerate(samples, 1):
        hex_plain = f"{plaintext:04X}"
        key = "".join(f"{part:04X}" for part in keys)
        if mode == "block":
            a_cipher = encrypt_block(plaintext, *keys)
            b_cipher = block_call("encrypt", hex_plain, key)
            b_plain = block_call("decrypt", f"{a_cipher:04X}", key)
            a_plain = decrypt_block(b_cipher, *keys)
        elif mode == "double":
            a_cipher = double_encrypt(plaintext, *keys)
            b_cipher = block_call("double-encrypt", key, hex_plain)
            b_plain = block_call("double-decrypt", key, f"{a_cipher:04X}")
            a_plain = double_decrypt(b_cipher, *keys)
        else:
            a_cipher = triple_encrypt(plaintext, *keys, mode="eee")
            b_cipher = block_call("triple-encrypt", key, hex_plain)
            b_plain = block_call("triple-decrypt", key, f"{a_cipher:04X}")
            a_plain = triple_decrypt(b_cipher, *keys, mode="eee")
        passed = a_cipher == b_cipher and a_plain == plaintext and b_plain == plaintext
        rows.append(dict(id=index, mode=mode, plaintext=hex_plain, key=key,
                         a_cipher=f"{a_cipher:04X}", b_cipher=f"{b_cipher:04X}",
                         b_decrypt_a=f"{b_plain:04X}", a_decrypt_b=f"{a_plain:04X}",
                         cipher_equal=a_cipher == b_cipher, b_decrypt_ok=b_plain == plaintext,
                         a_decrypt_ok=a_plain == plaintext, result="PASS" if passed else "FAIL"))
        if index % 200 == 0:
            print(f"Checked {index}/{len(samples)} cases", flush=True)

    with (output / "results.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    # Record actual protocol differences; do not hide them by changing either implementation.
    differences = []
    for text in ("AB", "ABC"):
        differences.append({"plaintext": text,
            "a_ascii": ascii_encrypt(text, 0x4AF5).hex().upper(),
            "b_ascii": call("encrypt-text", "4AF5", text),
            "a_cbc": cbc_encrypt(text.encode("ascii"), 0x4AF5, 0x1234).hex().upper(),
            "b_cbc": call("cbc-encrypt", "4AF5", "1234", text)})
    counts = {mode: {"total": sum(row["mode"] == mode for row in rows),
                     "failed": sum(row["mode"] == mode and row["result"] == "FAIL" for row in rows)}
              for mode in ("block", "double", "eee")}
    summary = {"timestamp": datetime.now(timezone(timedelta(hours=8))).isoformat(),
               "python": sys.version, "platform": platform.platform(), "seed": args.seed,
               "peer_dir": str(peer), "peer_execution": "supplied saes.exe; not rebuilt locally",
               "source_binary_correspondence": "not independently verified",
               "sha256": hashes, "counts": counts, "padding_examples": differences,
               "command": subprocess.list2cmdline([sys.executable, *sys.argv])}
    (output / "metadata.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    failed = sum(row["result"] == "FAIL" for row in rows)
    lines = ["# Python / C++ 实际交叉测试报告", "",
             f"测试时间：{summary['timestamp']}（北京时间）；随机种子：{args.seed}。", "",
             "A：本项目 Python 实现；B：另一组 C++ 项目中的 saes.exe。",
             "测试在同一台Windows机器上执行。", "",
             "## 测试结果", "", "| 模式 | 样本数 | 失败数 |", "| --- | ---: | ---: |"]
    lines += [f"| {mode} | {value['total']} | {value['failed']} |" for mode, value in counts.items()]
    lines += ["", f"合计 {len(rows)} 组，{failed} 组失败。每组检查加密结果相同、B 解密 A 密文、A 解密 B 密文。",
              "基础分组使用 6 组固定输入和 1000 组随机输入；双重与三重 EEE 各使用 100 组随机输入。",
              "三重模式明确选择 EEE；未将本项目默认 EDE 与对方 EEE 混用。", "",
              "## 固定输入实测", "", "| P | K | A 密文 | B 密文 | B 解密 A | A 解密 B | 结果 |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    lines += [f"| {r['plaintext']} | {r['key']} | {r['a_cipher']} | {r['b_cipher']} | {r['b_decrypt_a']} | {r['a_decrypt_b']} | {r['result']} |" for r in rows[:6]]
    lines += ["", "## ASCII/CBC 协议差异", "",
              "A 使用 2 字节 PKCS#7 填充，B 仅对奇数长度补零、不去除填充。以下是原始接口实测值，不能将这些接口宣称为直接兼容。",
              "填充差异不影响基础单分组测试。", "",
              "| 明文 | A ASCII | B ASCII | A CBC | B CBC |", "| --- | --- | --- | --- | --- |"]
    lines += [f"| {d['plaintext']} | {d['a_ascii']} | {d['b_ascii']} | {d['a_cbc']} | {d['b_cbc']} |" for d in differences]
    lines += ["", "## 复现与版本", "",
              "- `results.csv`：全部样本的输入、双向解密结果与三个独立判定。",
              "- `metadata.json`：运行环境、完整命令、随机种子、双方源码及对方可执行文件的 SHA-256。",
              "- 使用对方提供的可执行文件；本机未重编译，未独立确认二进制与随附源码完全对应。",
              "- 未测试 EDE/EDE2、MITM 结果一致性或 GUI 互操作。", "",
              "在本项目目录运行：", "", "```powershell",
              f'python cross_test.py --peer-dir "{peer}"', "```", ""]
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(counts, ensure_ascii=False), flush=True)
    print(f"Report: {output / 'report.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
