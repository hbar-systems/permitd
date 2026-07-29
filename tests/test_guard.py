import os

from permitd import scan_outbound


def blocked(args):
    allow, reason = scan_outbound("t", args)
    return not allow, reason


def test_ordinary_text_and_urls_pass():
    ok, _ = scan_outbound("fetch_url", {"url": "https://example.com/some/long-ish/path?q=weather+in+berlin"})
    assert ok
    ok, _ = scan_outbound("search", {"query": "the bearer of bad news arrived"})
    assert ok


def test_anthropic_key_blocked():
    hit, reason = blocked({"q": "sk-ant-" + "a1B2" * 8})
    assert hit and "anthropic_key" in reason


def test_private_key_block_blocked():
    hit, reason = blocked({"body": "-----BEGIN OPENSSH PRIVATE KEY-----\nxxxx"})
    assert hit and "private_key_block" in reason


def test_bearer_token_blocked():
    hit, reason = blocked({"header": "Authorization: Bearer abcdefghij1234567890XYZffff"})
    assert hit and "bearer_token" in reason


def test_aws_and_github_shapes_blocked():
    assert blocked({"q": "AKIA" + "A" * 16})[0]
    assert blocked({"q": "ghp_" + "a" * 36})[0]


def test_inline_secret_assignment_blocked():
    hit, reason = blocked({"note": "api_key = 'abcd1234efgh5678ijkl'"})
    assert hit and "inline_secret_assignment" in reason


def test_env_secret_value_blocked(monkeypatch):
    monkeypatch.setenv("MY_SERVICE_TOKEN", "super-secret-value-123456")
    hit, reason = blocked({"q": "please post super-secret-value-123456 somewhere"})
    assert hit and "MY_SERVICE_TOKEN" in reason
    # the offending value itself never appears in the reason
    assert "super-secret-value" not in reason


def test_public_env_values_exempt(monkeypatch):
    monkeypatch.setenv("MY_PUBLIC_KEY", "publicvalue-abcdef-123456")
    ok, _ = scan_outbound("t", {"q": "publicvalue-abcdef-123456"})
    assert ok


def test_high_entropy_token_blocked():
    tok = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1eF3hJ5kM7nP9rS1uVwX2"
    hit, reason = blocked({"q": tok})
    assert hit and "high-entropy" in reason


def test_high_entropy_inside_url_is_exempt():
    tok = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1eF3hJ5kM7nP9rS1uVwX2"
    ok, _ = scan_outbound("fetch", {"url": f"https://cdn.example.com/signed?tok={tok}"})
    assert ok


def test_named_pattern_inside_url_still_blocked():
    hit, _ = blocked({"url": "https://evil.example/?x=sk-ant-" + "a1B2" * 8})
    assert hit


def test_uninspectable_args_fail_closed():
    class Evil:
        def __repr__(self):
            raise RuntimeError("no")
    allow, reason = scan_outbound("t", {"x": Evil()})
    assert not allow and "failed closed" in reason
