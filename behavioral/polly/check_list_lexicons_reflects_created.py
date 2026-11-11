"""list-lexicons-reflects-created."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-lexicons-reflects-created"
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
    """ListLexicons enumerates every stored lexicon and stops reflecting one
    the moment it is deleted -- exercising create/list/delete as one system."""
    polly = ctx.client("polly")
    names = [_lexicon_name(ctx, f"m{i}") for i in range(3)]
    for name in names:
        polly.put_lexicon(Name=name, Content=_PLS)
        ctx.on_cleanup(lambda n=name: _safe_delete(polly, n))

    listed = {e["Name"] for e in _list_all(polly)}
    for name in names:
        assert name in listed, f"{name} missing from ListLexicons after PutLexicon"

    # delete the middle one and confirm it disappears while the others remain
    polly.delete_lexicon(Name=names[1])
    listed_after = {e["Name"] for e in _list_all(polly)}
    assert names[1] not in listed_after, f"{names[1]} still in ListLexicons after DeleteLexicon: {listed_after}"
    assert names[0] in listed_after, f"{names[0]} missing from ListLexicons after unrelated delete: {listed_after}"
    assert names[2] in listed_after, f"{names[2]} missing from ListLexicons after unrelated delete: {listed_after}"

    # the deleted lexicon is not just absent from the list -- it is gone and unusable
    code, message = _error_code(lambda: polly.get_lexicon(Name=names[1]))
    assert code == "LexiconNotFoundException", f"expected LexiconNotFoundException for deleted {names[1]}, got {code}"
    assert message == "Lexicon not found", message


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
