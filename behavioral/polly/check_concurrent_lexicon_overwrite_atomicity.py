"""concurrent-lexicon-overwrite-atomicity."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-lexicon-overwrite-atomicity"
GROUP = "concurrency"
SERVICES = ["polly"]


def _pls_for(tag: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>racer</grapheme><alias>{tag}</alias></lexeme>
</lexicon>
"""


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """Concurrent PutLexicon calls on one Name never mix writers' bytes: GetLexicon afterwards
    returns exactly one racer's full, well-formed document, as PutLexicon overwrites the whole
    lexicon."""
    polly = ctx.client("polly")
    name = _lexicon_name(ctx, "race")
    n_racers = 8
    contents = {f"racer{i}": _pls_for(f"racer{i}") for i in range(n_racers)}

    # seed it first so every racer is an overwrite, not a creation race
    polly.put_lexicon(Name=name, Content=contents["racer0"])
    ctx.on_cleanup(lambda: _safe_delete(polly, name))

    def _put(tag: str) -> None:
        polly.put_lexicon(Name=name, Content=contents[tag])

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        list(pool.map(_put, contents.keys()))

    final = polly.get_lexicon(Name=name)["Lexicon"]["Content"].strip()
    matches = [tag for tag, content in contents.items() if content.strip() == final]
    assert len(matches) == 1, (
        f"final content did not exactly match exactly one racer's document: "
        f"matches={matches} final={final!r}"
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
