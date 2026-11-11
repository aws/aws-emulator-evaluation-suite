"""delete-lexicon-removes-from-list."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-lexicon-removes-from-list"
GROUP = "state"
SERVICES = ["polly"]

_PLS = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>foo</grapheme><alias>bar</alias></lexeme>
</lexicon>
"""


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """DeleteLexicon removes the lexicon from ListLexicons while a sibling stays listed, GetLexicon
    on the deleted name fails with LexiconNotFoundException, and the freed name can be stored
    again at once."""
    polly = ctx.client("polly")
    target_name = _lexicon_name(ctx, "tgt")
    control_name = _lexicon_name(ctx, "ctl")

    polly.put_lexicon(Name=target_name, Content=_PLS)
    polly.put_lexicon(Name=control_name, Content=_PLS)
    ctx.on_cleanup(lambda: _safe_delete(polly, control_name))
    ctx.on_cleanup(lambda: _safe_delete(polly, target_name))

    listed_before = {e["Name"] for e in _list_all(polly)}
    assert target_name in listed_before, f"{target_name} missing from ListLexicons after PutLexicon"
    assert control_name in listed_before, f"{control_name} missing from ListLexicons after PutLexicon"

    polly.delete_lexicon(Name=target_name)

    listed_after = {e["Name"] for e in _list_all(polly)}
    assert target_name not in listed_after, f"{target_name} still listed after DeleteLexicon"
    assert control_name in listed_after, f"sibling {control_name} vanished from the list too"

    code, message = _error_code(lambda: polly.get_lexicon(Name=target_name))
    assert code == "LexiconNotFoundException", f"expected LexiconNotFoundException, got {code}"
    assert message == "Lexicon not found", message

    # the freed name is immediately reusable, and reappears in an independent read
    polly.put_lexicon(Name=target_name, Content=_PLS)
    listed_final = {e["Name"] for e in _list_all(polly)}
    assert target_name in listed_final, f"recreated {target_name} did not reappear in ListLexicons"


def _lexicon_name(ctx: Any, tag: str = "") -> str:
    raw = ctx.unique_name(f"l{tag}")
    cleaned = "".join(c for c in raw if c.isalnum())
    return cleaned[:20] or f"lex{tag}"


def _list_all(polly):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = polly.list_lexicons(**kwargs)
        out.extend(resp["Lexicons"])
        token = resp.get("NextToken")
        if not token:
            return out


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
