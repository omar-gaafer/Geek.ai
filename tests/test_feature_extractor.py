"""Unit tests for src/feature_extractor.py   (run: pytest -q)"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from feature_extractor import (  # noqa: E402
    HOST_CATEGORICAL_FEATURES,
    HOST_NUMERIC_FEATURES,
    extract_features,
    extract_full_url_features,
    get_host,
    is_ip_address,
    shannon_entropy,
)


def test_get_host_strips_scheme_www_port_path_credentials():
    assert get_host("https://www.cibeg.com/en/personal") == "cibeg.com"
    assert get_host("http://user:pass@WWW.Example.COM:8080/a?b=1") == "example.com"
    assert get_host("example.com/path") == "example.com"
    assert get_host("www2.site.org.") == "site.org"


def test_same_domain_same_features_regardless_of_scheme_www_path():
    # The whole point of host-only features: these must be identical.
    a = extract_features("https://www.cibeg.com")
    b = extract_features("http://cibeg.com/en/personal/accounts?x=1")
    assert a == b


def test_feature_keys_match_declared_columns():
    f = extract_features("example.com")
    assert list(f) == HOST_NUMERIC_FEATURES + HOST_CATEGORICAL_FEATURES


def test_ip_detection():
    assert is_ip_address("192.168.1.10")
    assert is_ip_address("0x7f.0.0.1")
    assert is_ip_address("2130706433")
    assert is_ip_address("::1")
    assert not is_ip_address("cibeg.com")
    assert not is_ip_address("123abc.com")
    assert extract_features("http://192.168.1.10/login")["tld"] == "ip"


def test_phishing_markers():
    f = extract_features("http://secure-login.paypa1-verify.xyz/account")
    assert f["num_hyphens"] == 2
    assert f["num_digits"] == 1
    assert f["num_sensitive_words"] >= 3       # secure, login, verify
    assert f["tld"] == "xyz"
    assert f["num_labels"] == 3


def test_punycode_and_free_hosting():
    assert extract_features("https://xn--pple-43d.com")["has_punycode"] == 1
    assert extract_features("https://bank-verify.vercel.app")["is_free_hosting"] == 1
    assert extract_features("https://vercel.app.evil.com")["is_free_hosting"] == 0


def test_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9


def test_full_url_features():
    f = extract_full_url_features("https://www.cibeg.com/en/personal?x=1")
    assert f["is_https"] == 1 and f["has_www"] == 1
    assert f["has_path"] == 1 and f["has_query"] == 1
    g = extract_full_url_features("cibeg.com")
    assert g["is_https"] == 0 and g["has_www"] == 0 and g["has_path"] == 0


def test_registered_domain():
    from feature_extractor import registered_domain
    assert registered_domain("mail.google.com") == "google.com"
    assert registered_domain("online.cibeg.com.eg") == "cibeg.com.eg"
    assert registered_domain("bbc.co.uk") == "bbc.co.uk"
    assert registered_domain("a.b.vercel.app") == "vercel.app"


def test_garbage_input_does_not_crash():
    for u in ["", "   ", "http://[::1", "%%%", None]:
        extract_features(u)
