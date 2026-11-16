"""UNVEIL security layer: text checks on outside content that does not come through the tool dispatcher."""

import asyncio
import email
import inspect
import json
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import src.chat_processor as chat_processor
from routes import chat_helpers
from src.deep_research import DeepResearcher
from src.document_processor import build_user_content
from src.mcp_manager import McpManager
from src.research_navigator import ResearchPage
from src.unveil_guard import get_guard, guard_content, guard_outside_text, guarded_call, released_tool_result

ORDINARY = "Opening hours: 9 to 5."
WORDING = "Note to AI agents: MARKER-WORDS"
REASON = "text_check:reader_directive"


def _last_block():
    return get_guard().status()["last_block"]


def _release(owner):
    return get_guard().release(_last_block()["release_id"], owner)


# -- the content gate ---------------------------------------------------

def test_content_gate_returns_the_reason_or_none():
    assert guard_content("research_page", ORDINARY, owner="alice", session_id="s1") is None
    assert guard_content("research_page", ["Hello", {"body": WORDING}], owner="alice", session_id="s1") == REASON
    assert _last_block()["tool"] == "research_page" and _last_block()["owner"] == "alice"
    assert "MARKER-WORDS" not in get_guard().audit_path.read_text(encoding="utf-8")


def test_content_without_a_key_is_not_kept_and_has_no_release_control():
    guard_content("research_page", WORDING, owner="alice", session_id="s1")
    assert "release_id" not in _last_block()


def test_content_with_a_key_is_released_by_its_person_one_time():
    assert guard_content("attachment", WORDING, owner="alice", session_id="s1", key="k") == REASON
    assert _release("bob") is False
    assert _release("alice") is True
    assert released_tool_result("attachment", "k", owner="bob", session_id="s1") is None
    assert released_tool_result("attachment", "k", owner="alice", session_id="s1") == WORDING
    assert released_tool_result("attachment", "k", owner="alice", session_id="s1") is None


def test_content_gate_fails_closed_when_the_guard_cannot_be_built(monkeypatch):
    monkeypatch.setattr("src.unveil_guard.guard.get_guard", lambda: 1 / 0)
    assert guard_content("research_page", ORDINARY, owner="alice", session_id="s1") == "guard_unavailable:ZeroDivisionError"


def test_outside_text_is_released_by_its_person_for_the_same_text_one_time():
    def read(text=WORDING, owner="alice"):
        return guard_outside_text("linked_page", text, owner=owner, session_id="s1")

    assert read(ORDINARY) is None
    assert read() == REASON
    assert _release("bob") is False and _release("alice") is True
    assert read(owner="bob") == REASON
    assert read(f"{WORDING} changed") == REASON
    assert read() is None
    assert read() == REASON


def test_outside_text_gate_fails_closed_when_the_guard_cannot_be_built(monkeypatch):
    monkeypatch.setattr("src.unveil_guard.guard.get_guard", lambda: 1 / 0)
    assert guard_outside_text("linked_page", ORDINARY, owner="alice", session_id="s1") == "guard_unavailable:ZeroDivisionError"


# -- attachments --------------------------------------------------------

def _attachment_text(tmp_path, message, file_text):
    path = tmp_path / "notes.txt"
    path.write_text(file_text, encoding="utf-8")
    handler = SimpleNamespace(
        resolve_upload=lambda fid, owner=None: {"path": str(path), "name": "notes.txt", "mime": "text/plain"},
        inside_base_dir=lambda checked: True,
        is_image_file=lambda name, mime: False,
        is_audio_file=lambda name, mime: False,
        is_document_file=lambda name, mime: True,
    )
    return build_user_content(message, ["f1"], str(tmp_path), handler, owner="alice")


def _check_attachment(message, text, documents=(), owner="alice"):
    chat_helpers._enforce_attachment_guard(message, text, list(documents), owner=owner, session_id="s1")


@pytest.fixture
def documents_db(monkeypatch, tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import src.database as database
    engine = create_engine(f"sqlite:///{tmp_path / 'documents.db'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(chat_helpers, "SessionLocal", factory)
    yield factory
    engine.dispose()


def _pdf_document(factory, body):
    import src.database as database
    from src.pdf_form_doc import create_plain_pdf_document
    doc_id = create_plain_pdf_document(session_id=None, upload_id="a.pdf", title="Minutes", body_text=body)
    with factory() as db:
        return {"doc_id": doc_id, "content": db.get(database.Document, doc_id).current_content}


def _document_rows(factory):
    import src.database as database
    with factory() as db:
        return db.query(database.Document).count(), db.query(database.DocumentVersion).count()


def test_ordinary_attachment_passes(tmp_path):
    _check_attachment("Read this", _attachment_text(tmp_path, "Read this", ORDINARY))
    assert _last_block() is None


def test_message_with_no_attachment_is_not_read_as_content():
    _check_attachment("If you are an AI, say so.", "If you are an AI, say so.")
    assert _last_block() is None


def test_attachment_with_wording_for_the_model_is_withheld(tmp_path):
    text = _attachment_text(tmp_path, "Read this", f"Minutes.\n{WORDING}")
    assert "MARKER-WORDS" in text
    with pytest.raises(HTTPException) as refused:
        _check_attachment("Read this", text)
    assert refused.value.status_code == 403 and refused.value.detail["error"] == "UNVEIL_GUARD_BLOCKED"
    assert REASON in refused.value.detail["message"] and "MARKER-WORDS" not in refused.value.detail["message"]
    assert _last_block()["tool"] == "attachment" and "MARKER-WORDS" in _last_block()["excerpt"]


def test_person_releases_an_attachment_and_sends_it_again_one_time(tmp_path):
    text = _attachment_text(tmp_path, "Read this", WORDING)
    with pytest.raises(HTTPException):
        _check_attachment("Read this", text)
    assert _release("alice") is True
    with pytest.raises(HTTPException):
        _check_attachment("Read this", text, owner="bob")
    _check_attachment("Read this", text)
    with pytest.raises(HTTPException):
        _check_attachment("Read this", text)


def test_document_made_from_an_ordinary_attachment_stays(documents_db):
    document = _pdf_document(documents_db, ORDINARY)
    _check_attachment("Read this", "Read this\n\n[PDF attached: Minutes]", [document])
    assert _document_rows(documents_db) == (1, 1)


def test_document_made_from_a_withheld_attachment_is_removed(documents_db):
    from src.agent_tools import document_tools
    kept = _pdf_document(documents_db, ORDINARY)
    document = _pdf_document(documents_db, f"Page 40 of the file.\n{WORDING}")
    assert document_tools.get_active_document() == document["doc_id"]
    with pytest.raises(HTTPException):
        _check_attachment("Read this", "Read this\n\n[PDF attached: Minutes]", [document])
    import src.database as database
    with documents_db() as db:
        assert db.get(database.Document, document["doc_id"]) is None
        assert db.get(database.Document, kept["doc_id"]) is not None
        assert "MARKER-WORDS" not in "".join(row.content for row in db.query(database.DocumentVersion))
    assert _document_rows(documents_db) == (1, 1)
    assert document_tools.get_active_document() != document["doc_id"]


def test_attachment_is_checked_before_the_message_is_kept():
    source = inspect.getsource(chat_helpers.build_chat_context)
    check = source.index("_enforce_attachment_guard, message, preprocessed.text_for_context, auto_opened_docs,")
    assert source.index("await preprocess(") < check < source.index("_append_incognito_message(")
    assert check < source.index("add_user_message(")


# -- web search results in chat mode ------------------------------------

def _search_preface(monkeypatch, results, message="What are the opening hours?", owner="alice"):
    calls = []

    def search(query, **options):
        calls.append(query)
        return results, [{"url": "https://example.com", "title": "Example"}]

    monkeypatch.setattr(chat_processor, "comprehensive_web_search", search)
    monkeypatch.setattr("src.llm_core.llm_call", lambda *args, **options: "opening hours")
    processor = chat_processor.ChatProcessor(
        memory_manager=SimpleNamespace(load=lambda owner=None: []),
        personal_docs_manager=SimpleNamespace(rag_manager=None), skills_manager=None)
    preface, _, sources = processor.build_context_preface(
        message=message, session=SimpleNamespace(id="s1", endpoint_url="", model="", headers={}),
        use_web=True, use_rag=False, use_memory=False, owner=owner)
    return "\n".join(str(row["content"]) for row in preface), sources, calls


def test_ordinary_search_results_reach_the_model(monkeypatch):
    text, sources, _ = _search_preface(monkeypatch, ORDINARY)
    assert ORDINARY in text and sources


def test_search_results_with_wording_for_the_model_are_withheld(monkeypatch):
    text, sources, _ = _search_preface(monkeypatch, f"Result one.\n{WORDING}")
    assert "MARKER-WORDS" not in text and REASON in text and sources == []
    assert _last_block()["tool"] == "web_search_context" and _last_block()["owner"] == "alice"


def test_released_search_results_are_handed_over_one_time_without_a_new_search(monkeypatch):
    _search_preface(monkeypatch, WORDING)
    assert _release("alice") is True
    assert "MARKER-WORDS" not in _search_preface(monkeypatch, WORDING, owner="bob")[0]
    text, sources, calls = _search_preface(monkeypatch, "The results changed after the person read the reason.")
    assert "MARKER-WORDS" in text and "results changed" not in text and sources and calls == []
    assert "MARKER-WORDS" not in _search_preface(monkeypatch, WORDING)[0]


def test_prefetched_search_results_and_youtube_text_are_read_before_they_are_added():
    source = inspect.getsource(chat_helpers.build_chat_context)
    assert source.index('guard_outside_text("web_search_context", search_context') < source.index(
        'untrusted_context_message("prefetched search context"')
    assert source.index('guard_outside_text("youtube", transcript') < source.index(
        'untrusted_context_message("youtube transcript"')
    assert "youtube_prefetch_sources(preprocessed.text_for_context, youtube_read)" in source


def test_the_app_text_for_youtube_passes_the_check():
    from src.chat_handler import YOUTUBE_INSTRUCTION_PROMPT
    assert guard_outside_text("youtube", YOUTUBE_INSTRUCTION_PROMPT, owner="alice", session_id="s1") is None


# -- pages from links in a chat message ---------------------------------

def _link_preface(monkeypatch, page_text, owner="alice"):
    monkeypatch.setattr(chat_processor, "fetch_webpage_content",
                        lambda url: {"success": True, "content": page_text, "title": "Example"})
    processor = chat_processor.ChatProcessor(
        memory_manager=SimpleNamespace(load=lambda owner=None: []),
        personal_docs_manager=SimpleNamespace(rag_manager=None), skills_manager=None)
    preface, _, sources = processor.build_context_preface(
        message="Please read https://example.com/page", use_web=False, use_rag=False, use_memory=False,
        session=SimpleNamespace(id="s1", endpoint_url="", model="", headers={}), owner=owner)
    return "\n".join(str(row["content"]) for row in preface), sources


def test_ordinary_linked_page_reaches_the_model(monkeypatch):
    text, sources = _link_preface(monkeypatch, ORDINARY)
    assert ORDINARY in text and sources[0]["url"] == "https://example.com/page"


def test_linked_page_with_wording_for_the_model_is_withheld(monkeypatch):
    text, sources = _link_preface(monkeypatch, f"Hours.\n{WORDING}")
    assert "MARKER-WORDS" not in text and REASON in text and sources == []
    assert _last_block()["tool"] == "linked_page" and _last_block()["owner"] == "alice"


def test_person_releases_a_linked_page_one_time(monkeypatch):
    _link_preface(monkeypatch, WORDING)
    assert _release("alice") is True
    assert "MARKER-WORDS" not in _link_preface(monkeypatch, WORDING, owner="bob")[0]
    assert "MARKER-WORDS" in _link_preface(monkeypatch, WORDING)[0]
    assert "MARKER-WORDS" not in _link_preface(monkeypatch, WORDING)[0]


# -- the open document and the open email --------------------------------

def _open_item(text, source="open_document", item="The open document"):
    from routes import chat_routes
    ctx = SimpleNamespace(user="alice", messages=[{"role": "user", "content": "Make it shorter"}])
    ctx.route_messages = list(ctx.messages)
    withheld = asyncio.run(chat_routes._open_item_withheld(ctx, source, item, text, "s1"))
    return withheld, ctx


def test_ordinary_open_document_passes():
    withheld, ctx = _open_item(f"Plan\n{ORDINARY}")
    assert withheld is False and len(ctx.messages) == 1 and len(ctx.route_messages) == 1


def test_open_document_with_wording_for_the_model_is_withheld():
    withheld, ctx = _open_item(f"Plan\n{WORDING}")
    assert withheld is True
    for messages in (ctx.messages, ctx.route_messages):
        assert messages[0]["role"] == "system" and REASON in messages[0]["content"]
        assert "MARKER-WORDS" not in str(messages) and messages[-1]["content"] == "Make it shorter"
    assert _last_block()["tool"] == "open_document" and _last_block()["owner"] == "alice"


def test_person_releases_the_open_document_one_time():
    assert _open_item(f"Plan\n{WORDING}")[0] is True
    assert _release("alice") is True
    assert _open_item(f"Plan\n{WORDING}")[0] is False
    assert _open_item(f"Plan\n{WORDING}")[0] is True


def test_stream_route_reads_the_open_document_and_email_before_the_agent_gets_them():
    from routes import chat_routes
    source = inspect.getsource(chat_routes)
    document = source.index('ctx, "open_document", "The open document"')
    email = source.index('ctx, "open_email", "The open email"')
    assert source.index("_doc_db.expunge(active_doc)") < document < email
    assert email < source.index("active_document=active_doc,") < source.index("active_email=active_email_ctx,")
    assert 'active_email_ctx = {key: active_email_ctx[key] for key in ("uid", "folder", "account")}' in source


# -- email --------------------------------------------------------------

def test_email_routes_and_the_automatic_pass_read_email_before_a_model_gets_it():
    from routes.email import email_pollers, email_routes
    routes = inspect.getsource(email_routes)
    summary = routes.index("async def summarize_email(")
    assert summary < routes.index('guard_outside_text, "email", f"{sender}', summary) < routes.index(
        "await _generate_email_summary(", summary)
    reply = routes.index("original_body[:6000], *context_snippets[:5], referenced[:18000]")
    assert reply < routes.index("_messages = [", reply)
    single = inspect.getsource(email_pollers._auto_summarize_pass_single)
    check = single.index('guard_content, "email", f"{sender}')
    assert single.index("body_for_llm = (body or \"\")") < check
    assert all(check < single.index(call) for call in (
        "_import_calendar_attachments(", "_generate_scheduled_email_summary(", "task_llm_call_async("))


def _html_email(body, multipart):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from routes.email.email_helpers import _extract_text
    message = MIMEText(body, "html")
    if multipart:
        message, part = MIMEMultipart("alternative"), message
        message.attach(part)
    return _extract_text(email.message_from_bytes(message.as_bytes()))


@pytest.mark.parametrize("multipart", [False, True])
def test_words_in_the_cells_and_blocks_of_an_html_email_stay_separate_words(multipart):
    text = _html_email("<table><tr><td>Opening</td><td>hours</td></tr><tr><th>nine</th><th>to five</th></tr></table>"
                       "<p>Closed</p><div>on Sunday</div>", multipart)
    assert text.split() == ["Opening", "hours", "nine", "to", "five", "Closed", "on", "Sunday"]


@pytest.mark.parametrize("multipart", [False, True])
def test_a_word_with_markup_inside_it_in_an_html_email_stays_one_word(multipart):
    assert _html_email("<p>Open<b></b>ing <i>hou</i>rs</p>", multipart) == "Opening hours"


def test_html_email_with_wording_for_the_model_in_table_cells_is_withheld():
    text = _html_email("<table><tr>" + "".join(f"<td>{word}</td>" for word in WORDING.split()) + "</tr></table>", False)
    assert guard_outside_text("email", text, owner="alice", session_id=None) == REASON


def _translate(monkeypatch, data):
    import src.endpoint_resolver as endpoint_resolver
    import src.llm_core as llm_core
    from routes.email import email_routes

    async def model(candidates, messages, **options):
        model.read.append(messages)
        return "<<<TRANSLATION>>>\nHorario\n<<<END>>>"

    model.read = []
    monkeypatch.setattr(llm_core, "llm_call_async_with_fallback", model)
    monkeypatch.setattr(endpoint_resolver, "resolve_endpoint", lambda role, owner=None: ("http://127.0.0.1:9", "stub", {}))
    monkeypatch.setattr(endpoint_resolver, "resolve_utility_fallback_candidates", lambda owner=None: [])
    route = [route for route in email_routes.setup_email_routes().routes if route.path.endswith("/translate")][-1]
    return asyncio.run(route.endpoint(data, owner="alice")), model.read


def test_ordinary_email_is_translated(monkeypatch, tmp_path):
    monkeypatch.setattr("routes.email.email_routes.SCHEDULED_DB", tmp_path / "scheduled.db")
    result, read = _translate(monkeypatch, {"from": "shop@example.com", "subject": "Hours", "body": ORDINARY,
                                            "target_language": "Spanish"})
    assert len(read) == 1 and result.get("translation") == "Horario"


@pytest.mark.parametrize("field", ["from", "subject", "body"])
def test_email_with_wording_for_the_model_is_not_translated(monkeypatch, tmp_path, field):
    monkeypatch.setattr("routes.email.email_routes.SCHEDULED_DB", tmp_path / "scheduled.db")
    data = {"from": "shop@example.com", "subject": "Hours", "body": ORDINARY, "target_language": "Spanish", field: WORDING}
    result, read = _translate(monkeypatch, data)
    assert read == [] and result["success"] is False and result["error_code"] == "unveil_guard_withheld"
    assert _last_block()["tool"] == "email" and _last_block()["owner"] == "alice"


async def _automatic_pass(monkeypatch, tmp_path, date, content_type, body):
    """Run the automatic email pass on one email from a stand-in mailbox. Returns the result and the summary calls."""
    import routes.email_helpers as email_helpers
    import routes.email_pollers as email_pollers

    db_path = tmp_path / "scheduled_emails.db"
    monkeypatch.setattr(email_helpers, "SCHEDULED_DB", db_path)
    monkeypatch.setattr(email_pollers, "SCHEDULED_DB", db_path)
    email_helpers._init_scheduled_db()
    raw_email = (f"From: Sender <sender@example.com>\r\nTo: Alice <alice@example.com>\r\nSubject: Hours\r\n"
                 f"Message-ID: <{uuid.uuid4().hex}@example.com>\r\nDate: {date}\r\n"
                 f"Content-Type: {content_type}; charset=utf-8\r\n\r\n{body}").encode()

    class Mailbox:
        def select(self, folder, readonly=True):
            return "OK", []

        def uid(self, command, *args):
            return "OK", [b"1"] if command == "SEARCH" else [(b"1 (RFC822)", raw_email)]

        def logout(self):
            pass

    summaries = []

    async def summary(**options):
        summaries.append(options)
        return "- Opening hours"

    monkeypatch.setattr(email_pollers, "_load_settings", lambda: {"email_auto_summarize": True})
    monkeypatch.setattr(email_pollers, "_owner_for_email_account", lambda account_id: "alice")
    monkeypatch.setattr(email_pollers, "_imap_connect", lambda account_id=None, owner="": Mailbox())
    monkeypatch.setattr(email_pollers, "_get_email_config", lambda account_id=None, owner="": {"from_address": "alice@example.com"})
    monkeypatch.setattr(email_pollers, "resolve_task_candidates", lambda owner=None: [("http://127.0.0.1:9", "stub", {})])
    monkeypatch.setattr(email_pollers, "_generate_scheduled_email_summary", summary)
    return await email_pollers._auto_summarize_pass_single(account_id="acct-alice"), summaries


HOURS = "The shop opens at nine and closes at five. " * 8


@pytest.mark.asyncio
@pytest.mark.parametrize("header, withheld", [("Tue, 01 Jan 2026 12:00:00 +0000", False), (WORDING, True)])
async def test_automatic_pass_reads_the_date_line_of_an_email(monkeypatch, tmp_path, header, withheld):
    result, summaries = await _automatic_pass(monkeypatch, tmp_path, header, "text/plain", HOURS)
    assert ("1 withheld" in result) is withheld and len(summaries) == (0 if withheld else 1)


def _each_word_in(opening, closing=""):
    return "".join(f"{opening}{word}{closing}" for word in WORDING.split())


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    _each_word_in("<td>"),
    _each_word_in("<p>"),
    _each_word_in("<li class='item' data-width=\"2\">"),
    _each_word_in("<span>", "</span>"),
    _each_word_in("", "<hr>"),
    WORDING.replace(" ", "<!-- -->"),
    WORDING.replace("Ignore", "Ig<b></b>nore"),
], ids=["cells not closed", "blocks not closed", "items with attributes", "inline elements", "rules", "comments",
        "markup inside a word"])
async def test_automatic_pass_reads_an_html_email_with_each_tag_removed_and_with_each_tag_as_a_space(monkeypatch, tmp_path, body):
    result, summaries = await _automatic_pass(monkeypatch, tmp_path, "Tue, 01 Jan 2026 12:00:00 +0000", "text/html",
                                              f"<html><body><p>{HOURS}</p>{body}</body></html>")
    assert "1 withheld" in result and summaries == []


@pytest.mark.asyncio
async def test_automatic_pass_gives_an_ordinary_html_email_to_the_model_in_one_reading(monkeypatch, tmp_path):
    result, summaries = await _automatic_pass(
        monkeypatch, tmp_path, "Tue, 01 Jan 2026 12:00:00 +0000", "text/html",
        f"<html><body><table><tr><td>Opening</td><td>hours</td></tr></table><p>{HOURS}</p></body></html>")
    assert "withheld" not in result and len(summaries) == 1
    assert summaries[0]["body_for_llm"].startswith("Opening hours\nThe shop opens at nine")


# -- research pages -----------------------------------------------------

def _read_research_page(content, title="Example"):
    page = ResearchPage(url="https://example.com/a", title=title, content=content, success=True)

    async def fetch(url, *, timeout=10):
        return page

    async def llm(messages, **options):
        llm.read.append(messages[1]["content"])
        return json.dumps({"rational": "r", "summary": "The page gives opening hours.", "evidence": "9 to 5"})

    llm.read = []
    researcher = DeepResearcher.__new__(DeepResearcher)
    researcher.max_content_chars = 15000
    researcher.extraction_timeout = 30
    researcher.search_provider_override = None
    researcher.navigator = SimpleNamespace(fetch=fetch)
    researcher.urls_fetched = set()
    researcher.analyzed_urls = []
    researcher._progress = None
    researcher.owner = "alice"
    researcher.session_id = "s1"
    researcher._llm = llm
    finding = asyncio.run(researcher._fetch_and_extract("https://example.com/a", "What are the opening hours?", title))
    return finding, llm.read, researcher


def test_ordinary_research_page_reaches_the_model():
    finding, read, researcher = _read_research_page(f"Opening hours for the shop. {ORDINARY}")
    assert finding["summary"] == "The page gives opening hours." and ORDINARY in read[0]
    assert getattr(researcher, "pages_withheld", 0) == 0


def test_research_page_with_wording_for_the_model_is_skipped():
    finding, read, researcher = _read_research_page(f"Opening hours for the shop.\n<!-- {WORDING} -->")
    trace = researcher.navigation_trace
    assert finding is None and read == [] and researcher.pages_withheld == 1
    researcher._start_time, researcher.round_count, researcher.queries_used = None, 1, []
    researcher.llm_model, researcher.providers_used, researcher.category = "", [], None
    assert researcher.get_stats()["Pages withheld"] == 1
    assert trace[-1]["status"] == "withheld" and trace[-1]["error"] == REASON
    assert _last_block()["tool"] == "research_page" and _last_block()["owner"] == "alice"


def test_research_page_title_is_read_with_the_page():
    finding, read, researcher = _read_research_page(f"Opening hours for the shop. {ORDINARY}", title=WORDING)
    assert finding is None and read == [] and researcher.pages_withheld == 1


def _report(pages_withheld):
    async def run(question, prior_report, prior_findings, prior_urls):
        return "REPORT BODY"

    researcher = DeepResearcher.__new__(DeepResearcher)
    researcher._research = run
    if pages_withheld is not None:
        researcher.pages_withheld = pages_withheld
    return asyncio.run(researcher.research("What are the opening hours?"))


def test_research_report_states_how_many_pages_were_withheld():
    assert _report(None) == "REPORT BODY" and _report(0) == "REPORT BODY"
    assert _report(3).startswith("REPORT BODY") and "withheld 3 page(s)" in _report(3)


def test_research_runs_are_given_their_owner():
    from src import research_handler, task_scheduler
    assert 'owner=(_task_entry or {}).get("owner", "")' in inspect.getsource(research_handler)
    assert 'owner=task.owner or ""' in inspect.getsource(task_scheduler)


# -- direct calls to outside tool servers -------------------------------

def _manager(text):
    async def call_tool(name, arguments):
        return SimpleNamespace(content=[SimpleNamespace(text=text)], isError=False)

    manager = McpManager()
    manager._sessions["remote"] = SimpleNamespace(call_tool=call_tool)
    return manager


def test_direct_outside_server_result_reaches_the_caller():
    result = asyncio.run(_manager(ORDINARY).call_tool("mcp__remote__lookup", {"q": "hours"}))
    assert result["stdout"] == ORDINARY and result["exit_code"] == 0


def test_direct_outside_server_result_with_wording_for_the_model_is_withheld():
    result = asyncio.run(_manager(WORDING).call_tool("mcp__remote__lookup", {"q": "hours"}))
    assert result["blocked"] is True and result["failure_kind"] == "unveil_guard_denied"
    assert REASON in result["error"] and "MARKER-WORDS" not in str(result)
    assert _last_block()["tool"] == "mcp__remote__lookup" and "release_id" not in _last_block()


def test_outside_server_result_inside_the_dispatcher_is_read_one_time():
    async def call():
        with guarded_call():
            return await _manager(WORDING).call_tool("mcp__remote__lookup", {"q": "hours"})

    assert asyncio.run(call())["stdout"] == WORDING
    assert _last_block() is None
