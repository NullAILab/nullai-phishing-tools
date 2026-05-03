"""
main.py — Phishing Domain & Quishing Scanner CLI

Subcommands:
    typosquat <domain>     Generate typosquat variants
    homoglyph <domain>     Generate Unicode homoglyph variants
    qr decode <image>      Decode QR code and analyse URL
    qr generate <url>      Generate a QR code image

Options:
    --check           Check which variants are registered (DNS lookup)
    --limit <n>       Max variants to show (default: 50)
    --json            JSON output
    --out <path>      Output path (qr generate only)

Usage:
    python main.py typosquat google.com --check
    python main.py homoglyph paypal.com --limit 20
    python main.py qr decode phishing_qr.png
    python main.py qr generate "https://evil.example.com" --out trap.png
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from phishing import (
    generate_typosquats, generate_homoglyphs, bulk_check,
    decode_qr, generate_qr, DomainVariant,
)

_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_RESET  = "\033[0m"


def render_variants(variants: list[DomainVariant], check: bool) -> None:
    if check:
        print(f"  {'Domain':<40} {'Technique':<16} Status")
        print(f"  {'─'*40} {'─'*16} {'─'*12}")
        for v in variants:
            status = (
                f"{_RED}REGISTERED{_RESET}" if v.registered
                else f"{_GREEN}available{_RESET}" if v.registered is False
                else "unchecked"
            )
            print(f"  {v.domain:<40} {v.technique:<16} {status}")
    else:
        for v in variants:
            print(f"  {v.domain:<40} {v.technique}")


def cmd_typosquat(args: argparse.Namespace) -> None:
    variants = generate_typosquats(args.domain)[:args.limit]
    if args.check:
        print(f"[*] Checking {len(variants)} domains (DNS)...")
        bulk_check(variants)

    if args.json:
        print(json.dumps([asdict(v) for v in variants], indent=2))
        return

    print(f"\n[*] Typosquat variants of {args.domain}  ({len(variants)} total)\n")
    render_variants(variants, args.check)

    if args.check:
        reg = [v for v in variants if v.registered]
        print(f"\n[!] {len(reg)} registered variant(s)" if reg else
              f"\n[+] No registered typosquat domains found")
    print()


def cmd_homoglyph(args: argparse.Namespace) -> None:
    variants = generate_homoglyphs(args.domain, max_variants=args.limit)
    if args.check:
        bulk_check(variants)

    if args.json:
        print(json.dumps([asdict(v) for v in variants], indent=2))
        return

    print(f"\n[*] Homoglyph variants of {args.domain}  ({len(variants)} total)\n")
    render_variants(variants, args.check)
    print()


def cmd_qr_decode(args: argparse.Namespace) -> None:
    results = decode_qr(args.image)
    if args.json:
        print(json.dumps({"image": args.image, "decoded": results}, indent=2))
        return

    print(f"\n[*] QR decode: {args.image}")
    for r in results:
        print(f"  → {r}")
        # Warn if it looks like a URL with a suspicious domain
        import re
        m = re.search(r"https?://([^/]+)", r)
        if m:
            host = m.group(1)
            print(f"    Host: {host}")
    print()


def cmd_qr_generate(args: argparse.Namespace) -> None:
    out = args.out or "qr_output.png"
    result = generate_qr(args.url, out)
    print(f"[+] QR code written to: {result}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing",
        description="Phishing domain generator and QR (quishing) scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--json",  action="store_true")
    p.add_argument("--check", action="store_true",
                   help="Check registration via DNS")
    p.add_argument("--limit", type=int, default=50)

    sub = p.add_subparsers(dest="command", required=True)

    ts = sub.add_parser("typosquat", help="Generate typosquat domains")
    ts.add_argument("domain")
    ts.set_defaults(func=cmd_typosquat)

    hg = sub.add_parser("homoglyph", help="Generate homoglyph domains")
    hg.add_argument("domain")
    hg.set_defaults(func=cmd_homoglyph)

    qr = sub.add_parser("qr", help="QR code decode or generate")
    qr_sub = qr.add_subparsers(dest="qr_command", required=True)

    qrd = qr_sub.add_parser("decode", help="Decode a QR code image")
    qrd.add_argument("image", help="Image file path")
    qrd.set_defaults(func=cmd_qr_decode)

    qrg = qr_sub.add_parser("generate", help="Generate a QR code image")
    qrg.add_argument("url",  help="URL or text to encode")
    qrg.add_argument("--out", default="qr_output.png")
    qrg.set_defaults(func=cmd_qr_generate)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
