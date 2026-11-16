import pytest

from agent.naming import NamingError, origin_text, public_name

SUFFIXES = (".corp.internal", ".internal")


@pytest.mark.parametrize("scheme, host, port, name", [
    ("https", "reports.corp.internal", 443, "reports.example.com"),
    ("https", "api.payroll.corp.internal", 443, "api-payroll.example.com"),
    ("https", "api.payroll.corp.internal", 8443, "api-payroll-8443.example.com"),
    ("http", "search.corp.internal", 9200, "search-9200.example.com"),
    ("http", "search.corp.internal", 80, "search.example.com"),
    ("https", "Queue.Internal", 443, "queue.example.com"),
    ("https", "partner.com", 443, "partner-com.example.com"),
])
def test_public_name(scheme, host, port, name):
    assert public_name(scheme, host, port, "example.com", SUFFIXES) == name


def test_a_name_that_is_not_a_dns_label_is_refused():
    with pytest.raises(NamingError):
        public_name("https", "x" * 70 + ".corp.internal", 443, "example.com", SUFFIXES)


@pytest.mark.parametrize("scheme, host, port, text", [
    ("https", "a.example", 443, "https://a.example"),
    ("http", "a.example", 8080, "http://a.example:8080"),
    ("https", "::1", 443, "https://[::1]"),
])
def test_origin_text(scheme, host, port, text):
    assert origin_text(scheme, host, port) == text
