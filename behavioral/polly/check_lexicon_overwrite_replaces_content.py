"""lexicon-overwrite-replaces-content."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lexicon-overwrite-replaces-content"
GROUP = "state"
SERVICES = ["polly"]

_PLS_V1 = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>AWS</grapheme><alias>A W S</alias></lexeme>
</lexicon>
"""

_PLS_V2 = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>AWS</grapheme><alias>Amazon Web Services</alias></lexeme>
  <lexeme><grapheme>GCP</grapheme><alias>Google Cloud Platform</alias></lexeme>
</lexicon>
"""


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """PutLexicon on an existing Name overwrites the stored content in place
    (create -> update transition), rather than erroring or appending."""
    polly = ctx.client("polly")
    name = _lexicon_name(ctx, "ow")

    polly.put_lexicon(Name=name, Content=_PLS_V1)
    ctx.on_cleanup(lambda: _safe_delete(polly, name))
    first = polly.get_lexicon(Name=name)
    first_count = first["LexiconAttributes"]["LexemesCount"]
    assert first_count == 1, f"expected 1 lexeme after initial PutLexicon, got {first_count}"

    polly.put_lexicon(Name=name, Content=_PLS_V2)
    second = polly.get_lexicon(Name=name)
    second_content = second["Lexicon"]["Content"].strip()
    assert second_content == _PLS_V2.strip(), (
        f"expected overwrite to replace content with V2, got {second_content!r}"
    )
    second_count = second["LexiconAttributes"]["LexemesCount"]
    assert second_count == 2, f"expected 2 lexemes after overwrite, got {second_count}"
    assert "Google Cloud Platform" in second["Lexicon"]["Content"], (
        "expected V2's new lexeme content in the stored document after overwrite"
    )

    # only one lexicon exists for this Name -- not a second entry
    listed = [e["Name"] for e in polly.list_lexicons()["Lexicons"]]
    assert listed.count(name) == 1, (
        f"expected exactly one lexicon named {name!r} after overwrite, got {listed.count(name)}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
