"""list-lexicons-invalid-next-token-error."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-lexicons-invalid-next-token-error"
GROUP = "error-semantics"
SERVICES = ["polly"]

_PLS = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>foo</grapheme><alias>bar</alias></lexeme>
</lexicon>
"""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """ListLexicons rejects a NextToken it never issued with InvalidNextTokenException, while the
    same call without a token succeeds and lists a lexicon created just before."""
    polly = ctx.client("polly")

    name = _lexicon_name(ctx)
    polly.put_lexicon(Name=name, Content=_PLS)
    ctx.on_cleanup(lambda: _safe_delete(polly, name))

    error, message = _error_code(
        lambda: polly.list_lexicons(NextToken="not-a-real-pagination-token")
    )
    assert error == "InvalidNextTokenException", (
        f"a NextToken never issued by ListLexicons was expected to raise "
        f"InvalidNextTokenException, got {error!r}"
    )
    assert message == "Invalid NextToken parameter", message

    # positive control: the identical operation with no token still works, and still reflects
    # the lexicon created above.
    resp = polly.list_lexicons()
    listed = {entry["Name"] for entry in resp["Lexicons"]}
    assert name in listed, f"{name!r} missing from ListLexicons after PutLexicon: {listed!r}"


def _lexicon_name(ctx) -> str:
    raw = ctx.unique_name("lnt")
    cleaned = "".join(c for c in raw if c.isalnum())
    return cleaned[:20] or "lexnt"


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
