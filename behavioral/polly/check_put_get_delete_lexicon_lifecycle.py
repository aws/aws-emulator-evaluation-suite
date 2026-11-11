"""put-get-delete-lexicon-lifecycle."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-get-delete-lexicon-lifecycle"
GROUP = "state"
SERVICES = ["polly"]

_PLS_VALID = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0"
    xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme>
    <grapheme>W3C</grapheme>
    <alias>World Wide Web Consortium</alias>
  </lexeme>
</lexicon>
"""


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """PutLexicon -> GetLexicon -> ListLexicons -> DeleteLexicon exercises the full
    lexicon state machine and each read reflects the stored content/attributes."""
    polly = ctx.client("polly")
    name = _lexicon_name(ctx, "lc")

    polly.put_lexicon(Name=name, Content=_PLS_VALID)
    ctx.on_cleanup(lambda: _safe_delete(polly, name))

    got = polly.get_lexicon(Name=name)
    assert got["Lexicon"]["Name"] == name, f"expected Name={name}, got {got['Lexicon']['Name']}"
    assert got["Lexicon"]["Content"].strip() == _PLS_VALID.strip(), (
        f"GetLexicon content diverged from what was Put: {got['Lexicon']['Content']!r}"
    )
    attrs = got["LexiconAttributes"]
    assert attrs["Alphabet"] == "ipa", f"expected Alphabet=ipa, got {attrs['Alphabet']!r}"
    assert attrs["LanguageCode"] == "en-US", f"expected LanguageCode=en-US, got {attrs['LanguageCode']!r}"
    assert attrs["LexemesCount"] == 1, f"expected LexemesCount=1, got {attrs['LexemesCount']!r}"
    assert attrs["LexiconArn"].endswith(f":lexicon/{name}"), (
        f"expected LexiconArn ending :lexicon/{name}, got {attrs['LexiconArn']!r}"
    )

    listed = polly.list_lexicons()["Lexicons"]
    names = [entry["Name"] for entry in listed]
    assert name in names, f"expected {name} in ListLexicons output, got {names}"
    matching = next(entry for entry in listed if entry["Name"] == name)
    assert matching["Attributes"]["LanguageCode"] == "en-US", (
        f"expected ListLexicons LanguageCode=en-US, got {matching['Attributes']['LanguageCode']!r}"
    )

    polly.delete_lexicon(Name=name)
    listed_after = [entry["Name"] for entry in polly.list_lexicons()["Lexicons"]]
    assert name not in listed_after, f"expected {name} absent from ListLexicons after delete, got {listed_after}"


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
