"""
feature_extractor.py
====================
Turns a raw URL into a small, explainable feature vector for phishing detection.

Design decision (see Phase 1 notebook, "shortcut" section):
    The training data (PhiUSIIL) has legit URLs that are ALWAYS "https://www.<domain>"
    with NO path, while phishing URLs often have paths, http, or no "www.".
    A model fed the full URL learns those collection artefacts instead of phishing.
    So the main features are computed from the HOSTNAME ONLY, after removing the
    scheme (http/https), "www.", the port, any user:pass@ part and the path.

Public API
----------
    get_host(url)                   -> normalised hostname, e.g. "paypa1-verify.xyz"
    extract_features(url)           -> dict of host-only features   (used by the model)
    extract_full_url_features(url)  -> host features + full-URL features (shortcut experiment only)
    HOST_NUMERIC_FEATURES, HOST_CATEGORICAL_FEATURES, FULL_URL_EXTRA_FEATURES
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

# --------------------------------------------------------------------------- #
# Word lists
# --------------------------------------------------------------------------- #
# Words attackers put in hostnames to look "official" / urgent.
SENSITIVE_WORDS = (
    "login", "logon", "signin", "sign-in", "verify", "verification", "account",
    "secure", "security", "update", "confirm", "bank", "banking", "wallet",
    "password", "otp", "support", "auth", "unlock", "billing", "payment", "webscr",
)

# Free hosting / site-builder platforms that are heavily abused for phishing.
FREE_HOSTING_SUFFIXES = (
    "vercel.app", "pages.dev", "workers.dev", "netlify.app", "github.io",
    "firebaseapp.com", "web.app", "blogspot.com", "weebly.com", "wixsite.com",
    "000webhostapp.com", "glitch.me", "herokuapp.com", "repl.co", "square.site",
    "godaddysites.com", "webflow.io", "framer.app", "ipfs.io", "r2.dev",
    "azurewebsites.net", "web.core.windows.net", "appspot.com", "gitbook.io",
)

VOWELS = set("aeiou")

# Column names (order matters: this is the order the model sees them)
HOST_NUMERIC_FEATURES = [
    "host_length",          # total characters in hostname
    "num_labels",           # number of dot-separated parts (a.b.c.com -> 4)
    "num_hyphens",          # '-' count
    "num_digits",           # digit count
    "digit_ratio",          # digits / length
    "vowel_ratio",          # vowels / letters (random-looking names have odd ratios)
    "entropy",              # Shannon entropy of the hostname (randomness)
    "longest_label",        # length of the longest part
    "is_ip",                # hostname is an IP address (incl. hex / decimal forms)
    "has_punycode",         # contains 'xn--' (IDN homograph trick)
    "num_sensitive_words",  # how many SENSITIVE_WORDS appear
    "is_free_hosting",      # hosted on a free platform (vercel.app, blogspot.com ...)
]
HOST_CATEGORICAL_FEATURES = ["tld"]   # top-level domain: com, xyz, eg ...

FULL_URL_EXTRA_FEATURES = [
    "url_length", "path_length", "has_path", "is_https", "has_www",
    "num_slashes", "has_query",
]

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_WWW_RE = re.compile(r"^www\d*\.")
_IPV4_DOTTED = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
# hex / octal / mixed dotted forms such as 0x7f.0.0.1 or 0177.0.0.1
_IPV4_OBFUSCATED = re.compile(r"^(0x[0-9a-f]+|0[0-7]*|\d+)(\.(0x[0-9a-f]+|0[0-7]*|\d+)){0,3}$")


def _split(url: str):
    """urlsplit that also works when the scheme is missing ('example.com/a')."""
    url = (url or "").strip()
    if not _SCHEME_RE.match(url):
        url = "http://" + url
    try:
        return urlsplit(url)
    except ValueError:          # e.g. malformed IPv6 brackets
        return urlsplit("http://invalid")


def get_host(url: str) -> str:
    """Normalised hostname: lower-case, no scheme, no 'www.', no port, no credentials."""
    host = _split(url).hostname or ""      # .hostname already lower-cases and drops port / user:pass@
    host = host.rstrip(".")
    host = _WWW_RE.sub("", host)
    return host


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0 for empty string)."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_ip_address(host: str) -> bool:
    """True for 1.2.3.4, IPv6, single decimal (2130706433) and hex/octal forms (0x7f.0.0.1)."""
    if not host:
        return False
    if ":" in host:                         # IPv6 (urlsplit strips the [ ])
        return True
    if _IPV4_DOTTED.match(host):
        return True
    # Pure numeric / hex host has no letters other than hex digits + 'x'
    if _IPV4_OBFUSCATED.match(host) and not re.search(r"[g-wyz]", host):
        return True
    return False


_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "sch", "gob", "or", "ne"}


def registered_domain(host: str) -> str:
    """Approximate 'owner' domain, used to keep one site out of both train and test.

    mail.google.com -> google.com ;  online.cibeg.com.eg -> cibeg.com.eg
    (Simple heuristic, no Public Suffix List download needed.)
    """
    if not host or is_ip_address(host):
        return host or "none"
    parts = host.split(".")
    if len(parts) > 2 and len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def get_tld(host: str) -> str:
    if not host:
        return "none"
    if is_ip_address(host):
        return "ip"
    return host.rsplit(".", 1)[-1]


# --------------------------------------------------------------------------- #
# Main API
# --------------------------------------------------------------------------- #
def extract_features(url: str) -> dict:
    """Host-only features. This is what the model is trained on."""
    host = get_host(url)
    labels = [p for p in host.split(".") if p]
    letters = [ch for ch in host if ch.isalpha()]
    digits = sum(ch.isdigit() for ch in host)
    ip = is_ip_address(host)

    return {
        "host_length": len(host),
        "num_labels": len(labels),
        "num_hyphens": host.count("-"),
        "num_digits": digits,
        "digit_ratio": digits / len(host) if host else 0.0,
        "vowel_ratio": (sum(ch in VOWELS for ch in letters) / len(letters)) if letters else 0.0,
        "entropy": shannon_entropy(host),
        "longest_label": max((len(p) for p in labels), default=0),
        "is_ip": int(ip),
        "has_punycode": int("xn--" in host),
        "num_sensitive_words": sum(w in host for w in SENSITIVE_WORDS),
        "is_free_hosting": int(any(host == s or host.endswith("." + s) for s in FREE_HOSTING_SUFFIXES)),
        "tld": get_tld(host),
    }


def extract_full_url_features(url: str) -> dict:
    """Host features + features of the whole URL.

    ONLY used in the notebook to demonstrate the shortcut-learning problem.
    Do not use for the real model.
    """
    feats = extract_features(url)
    raw = (url or "").strip()
    parts = _split(raw)
    path = parts.path or ""
    netloc_host = (parts.hostname or "")
    feats.update({
        "url_length": len(raw),
        "path_length": len(path),
        "has_path": int(len(path.strip("/")) > 0),
        "is_https": int(raw.lower().startswith("https://")),
        "has_www": int(bool(_WWW_RE.match(netloc_host))),
        "num_slashes": raw.count("/"),
        "has_query": int(bool(parts.query)),
    })
    return feats


if __name__ == "__main__":
    for u in [
        "https://www.cibeg.com/en/personal",
        "http://secure-login.paypa1-verify.xyz/account/update?id=1",
        "http://0x7f.0.0.1/login",
        "https://xn--pple-43d.com",
        "myapp-bank-verify.vercel.app",
    ]:
        print(u, "->", extract_features(u))
