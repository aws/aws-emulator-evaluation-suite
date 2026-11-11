"""get-lexicon-not-found-after-delete."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-lexicon-not-found-after-delete"
GROUP = "overly-permissive"
SERVICES = ["polly"]

_PLS = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>x</grapheme><alias>y</alias></lexeme>
</lexicon>
"""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """After DeleteLexicon, GetLexicon and a second DeleteLexicon on the Name both fail with
    LexiconNotFoundException, while a sibling lexicon stays readable."""
    polly = ctx.client("polly")
    deleted_name = _lexicon_name(ctx, "del")
    control_name = _lexicon_name(ctx, "ctl")

    polly.put_lexicon(Name=deleted_name, Content=_PLS)
    polly.put_lexicon(Name=control_name, Content=_PLS)
    ctx.on_cleanup(lambda: _safe_delete(polly, control_name))

    polly.delete_lexicon(Name=deleted_name)

    code_get, message_get = _error_code(lambda: polly.get_lexicon(Name=deleted_name))
    assert code_get == "LexiconNotFoundException", code_get
    assert message_get == "Lexicon not found", message_get

    code_delete, message_delete = _error_code(lambda: polly.delete_lexicon(Name=deleted_name))
    assert code_delete == "LexiconNotFoundException", code_delete
    assert message_delete == "Lexicon not found", message_delete

    # effect absent: it never reappears in the list
    listed = {e["Name"] for e in polly.list_lexicons()["Lexicons"]}
    assert deleted_name not in listed, f"deleted lexicon {deleted_name} reappeared in {listed}"

    # positive control: an unrelated, still-existing lexicon works fine
    control = polly.get_lexicon(Name=control_name)
    assert control["Lexicon"]["Name"] == control_name, control["Lexicon"]["Name"]


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
