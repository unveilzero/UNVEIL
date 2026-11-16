"""Long outside text with no structure is read in a short time: the time grows in step with the length."""
import email
import time

import pytest

LENGTH = 200_000
LIMIT_SECONDS = 0.5
BODIES = {"tag starts": "<" * LENGTH, "spaces": " " * LENGTH + "x", "open tags": "<p" * (LENGTH // 2)}


def _seconds(read, *args):
    started = time.perf_counter()
    read(*args)
    return time.perf_counter() - started


def _html_message(body):
    return email.message_from_string("Content-Type: text/html; charset=utf-8\n\n" + body)


@pytest.mark.parametrize("body", BODIES)
def test_html_email_is_read_in_a_short_time(body):
    from routes.email.email_helpers import _extract_text, _html_to_text
    assert _seconds(_extract_text, _html_message(BODIES[body])) < LIMIT_SECONDS
    assert _seconds(_html_to_text, BODIES[body], " ") < LIMIT_SECONDS


@pytest.mark.parametrize("body", BODIES)
def test_email_tool_reads_an_html_email_in_a_short_time(body):
    from mcp_servers.email_server import _extract_text
    assert _seconds(_extract_text, _html_message(BODIES[body])) < LIMIT_SECONDS


@pytest.mark.parametrize("body", BODIES)
def test_integration_response_is_read_in_a_short_time(body):
    from src.integrations import _strip_html_tags
    assert _seconds(_strip_html_tags, BODIES[body]) < LIMIT_SECONDS


def test_message_id_headers_are_read_in_a_short_time():
    from routes.email.email_routes import _message_id_chain
    assert _seconds(_message_id_chain, "<" * LENGTH, "<a@example.com> <b@example.com>") < LIMIT_SECONDS
    assert _message_id_chain("<a@example.com> <b@example.com>", "<a@example.com>") == ["<a@example.com>", "<b@example.com>"]
