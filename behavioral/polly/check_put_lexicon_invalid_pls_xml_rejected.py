"""put-lexicon-invalid-pls-xml-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-lexicon-invalid-pls-xml-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]

_VALID_PLS = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>ok</grapheme><alias>okay</alias></lexeme>
</lexicon>
"""

_NOT_PLS = "<not-a-lexicon>this is not valid PLS XML</not-a-lexicon>"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """PutLexicon rejects content that is not well-formed PLS with
    InvalidLexiconException, and never stores the malformed document -- while
    a well-formed PLS document (the positive control) is accepted normally."""
    polly = ctx.client("polly")
    bad_name = _lexicon_name(ctx, "bad")
    good_name = _lexicon_name(ctx, "good")

    code, message = _error_code(lambda: polly.put_lexicon(Name=bad_name, Content=_NOT_PLS))
    assert code == "InvalidLexiconException", f"expected InvalidLexiconException, got {code}"
    assert message == "Invalid PLS Lexicon", message

    # effect absent: the rejected lexicon was never persisted
    names = {e["Name"] for e in polly.list_lexicons()["Lexicons"]}
    assert bad_name not in names, f"expected {bad_name} absent from ListLexicons, found it in {names}"
    get_code, get_message = _error_code(lambda: polly.get_lexicon(Name=bad_name))
    assert get_code == "LexiconNotFoundException", f"expected LexiconNotFoundException, got {get_code}"
    assert get_message == "Lexicon not found", get_message

    # positive control: a well-formed PLS document is accepted
    polly.put_lexicon(Name=good_name, Content=_VALID_PLS)
    ctx.on_cleanup(lambda: _safe_delete(polly, good_name))
    stored = polly.get_lexicon(Name=good_name)
    assert stored["Lexicon"]["Name"] == good_name, (
        f"expected GetLexicon to return Name={good_name}, got {stored['Lexicon'].get('Name')}"
    )


def _lexicon_name(ctx: Any, tag: str = "") -> str:
    raw = ctx.unique_name(f"l{tag}")
    cleaned = "".join(c for c in raw if c.isalnum())
    return cleaned[:20] or f"lex{tag}"


def _safe_delete(polly, name: str) -> None:
    try:
        polly.delete_lexicon(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LexiconNotFoundException":
            raise


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
