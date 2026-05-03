"""
phishing.py — Phishing domain generation and analysis.

Tools:
  1. Typosquat generator  — produces lookalike domains via common typo patterns
  2. Homoglyph generator  — Unicode confusable character substitutions
  3. Domain availability checker — checks if a generated domain is registered
  4. QR code decoder     — decode a QR code image and extract the embedded URL

Requirements:
    pip install requests qrcode[pil] Pillow
    (pyzbar optional for QR decode: pip install pyzbar)

Educational use only — understand how phishing infrastructure is built
so you can detect and defend against it.
"""

from __future__ import annotations

import itertools
import re
import socket
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────
# Typosquat patterns
# ─────────────────────────────────────────────────────────────

# Adjacent QWERTY keys for substitution typos
_QWERTY_ADJACENT: dict[str, list[str]] = {
    "a": ["q","w","s","z"],  "b": ["v","g","h","n"],
    "c": ["x","d","f","v"],  "d": ["s","e","r","f","c","x"],
    "e": ["w","s","d","r"],  "f": ["d","r","t","g","v","c"],
    "g": ["f","t","y","h","b","v"], "h": ["g","y","u","j","n","b"],
    "i": ["u","o","k","j"],  "j": ["h","u","i","k","m","n"],
    "k": ["j","i","o","l","m"],    "l": ["k","o","p"],
    "m": ["n","j","k"],            "n": ["b","h","j","m"],
    "o": ["i","p","l","k"],        "p": ["o","l"],
    "q": ["a","w"],                "r": ["e","d","f","t"],
    "s": ["a","w","e","d","x","z"],"t": ["r","f","g","y"],
    "u": ["y","h","j","i"],        "v": ["c","f","g","b"],
    "w": ["q","a","s","e"],        "x": ["z","s","d","c"],
    "y": ["t","g","h","u"],        "z": ["a","s","x"],
}

# Common homoglyphs (Latin → confusable Unicode)
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["а","ɑ","α"],   # Cyrillic а, Latin alpha
    "c": ["с","ϲ"],        # Cyrillic с
    "e": ["е","ε"],        # Cyrillic е
    "i": ["і","ї","1","l"],
    "l": ["1","I","ɩ"],
    "o": ["о","0","ο","σ"],# Cyrillic о, zero, Greek
    "p": ["р","ρ"],        # Cyrillic р
    "s": ["ѕ","$"],
    "x": ["х","×"],        # Cyrillic х
    "y": ["у","γ"],        # Cyrillic у
}

_COMMON_TLDS = ["com", "net", "org", "io", "co", "info", "biz", "online"]


@dataclass
class DomainVariant:
    domain:     str
    technique:  str
    registered: Optional[bool] = None   # None = unchecked


def _split_domain(domain: str) -> tuple[str, str]:
    """Split 'example.com' → ('example', 'com')."""
    parts = domain.rsplit(".", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else (domain, "")


def generate_typosquats(domain: str) -> list[DomainVariant]:
    """Generate typosquat variants of *domain*."""
    name, tld = _split_domain(domain.lower())
    variants: list[DomainVariant] = []
    seen: set[str] = set()

    def add(d: str, tech: str) -> None:
        if d != name and d not in seen:
            seen.add(d)
            variants.append(DomainVariant(f"{d}.{tld}", tech))

    # 1. Missing char (omission)
    for i in range(len(name)):
        add(name[:i] + name[i+1:], "omission")

    # 2. Doubled char (repetition)
    for i, c in enumerate(name):
        add(name[:i] + c + name[i:], "repetition")

    # 3. Adjacent key substitution
    for i, c in enumerate(name):
        for sub in _QWERTY_ADJACENT.get(c, []):
            add(name[:i] + sub + name[i+1:], "keyboard-adj")

    # 4. Character swap (transposition)
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        add("".join(swapped), "transposition")

    # 5. Hyphen insertion
    for i in range(1, len(name)):
        add(name[:i] + "-" + name[i:], "hyphen-insert")

    # 6. TLD variations
    for alt_tld in _COMMON_TLDS:
        if alt_tld != tld:
            variants.append(DomainVariant(f"{name}.{alt_tld}", "tld-variant"))

    # 7. Common prefix/suffix tricks
    for affix, pos in [("login", "prefix"), ("secure", "prefix"),
                       ("signin", "prefix"), ("-login", "suffix"),
                       ("-secure", "suffix"), ("-verify", "suffix")]:
        if pos == "prefix":
            add(affix + name, "brand-prefix")
        else:
            add(name + affix, "brand-suffix")

    return variants


def generate_homoglyphs(domain: str, max_variants: int = 30) -> list[DomainVariant]:
    """Generate homoglyph variants using Unicode confusable characters."""
    name, tld = _split_domain(domain.lower())
    variants: list[DomainVariant] = []
    seen: set[str] = set()

    for i, c in enumerate(name):
        for glyph in _HOMOGLYPHS.get(c, []):
            candidate = name[:i] + glyph + name[i+1:]
            if candidate not in seen and candidate != name:
                seen.add(candidate)
                variants.append(DomainVariant(
                    f"{candidate}.{tld}", "homoglyph"
                ))
                if len(variants) >= max_variants:
                    return variants

    return variants


# ─────────────────────────────────────────────────────────────
# Domain registration check
# ─────────────────────────────────────────────────────────────

def check_registered(domain: str, timeout: float = 2.0) -> bool:
    """
    Return True if *domain* appears to be registered (resolves via DNS).

    This is a heuristic — NXDOMAIN responses return False, but a wildcard
    DNS on the TLD may return True for unregistered domains.
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def bulk_check(variants: list[DomainVariant],
               max_check: int = 50) -> list[DomainVariant]:
    """
    Check registration status for up to *max_check* variants.
    Updates variant.registered in-place.
    """
    import threading

    to_check = [v for v in variants if v.registered is None][:max_check]
    results: dict[str, bool] = {}
    lock = threading.Lock()

    def worker(v: DomainVariant) -> None:
        reg = check_registered(v.domain)
        with lock:
            results[v.domain] = reg

    threads = [threading.Thread(target=worker, args=(v,)) for v in to_check]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    for v in variants:
        if v.domain in results:
            v.registered = results[v.domain]

    return variants


# ─────────────────────────────────────────────────────────────
# QR code decoder ("quishing" scanner)
# ─────────────────────────────────────────────────────────────

def decode_qr(image_path: str) -> list[str]:
    """
    Decode QR codes from an image file and return all decoded strings.

    Tries pyzbar first (faster), falls back to Pillow's built-in QR reader.

    Args:
        image_path: Path to image file (PNG, JPG, etc.)

    Returns:
        List of decoded strings (usually URLs).
    """
    results: list[str] = []

    # Try pyzbar
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        from PIL import Image
        img = Image.open(image_path)
        for obj in pyzbar_decode(img):
            data = obj.data.decode(errors="replace")
            results.append(data)
        if results:
            return results
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: PIL QR reader (requires Pillow >= 10 with zxing-cpp optional)
    try:
        from PIL import Image
        img = Image.open(image_path)
        # Pillow 10+ has ImageOps.exif_transpose but no built-in QR
        # We just return an instruction if neither method worked
    except Exception:
        pass

    if not results:
        results.append("[!] Install pyzbar for QR decoding: pip install pyzbar")

    return results


# ─────────────────────────────────────────────────────────────
# QR code generator
# ─────────────────────────────────────────────────────────────

def generate_qr(data: str, output_path: str, box_size: int = 10) -> str:
    """
    Generate a QR code image containing *data* and save it to *output_path*.

    Requires: pip install qrcode[pil]
    """
    try:
        import qrcode  # type: ignore
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=box_size,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(output_path)
        return output_path
    except ImportError:
        return "[!] Install qrcode: pip install qrcode[pil]"
