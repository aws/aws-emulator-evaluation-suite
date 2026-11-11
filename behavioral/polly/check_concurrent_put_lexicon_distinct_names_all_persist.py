"""concurrent-put-lexicon-distinct-names-all-persist."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-put-lexicon-distinct-names-all-persist"
GROUP = "concurrency"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """Racing PutLexicon calls against N *distinct* names never cross-contaminate: every
    racer's own lexicon persists under its own name with exactly its own content, with no
    write landing under the wrong name."""
    polly = ctx.client("polly")
    racer_count = 8
    names = [_lexicon_name(ctx, f"iso{i}") for i in range(racer_count)]
    contents = {name: _pls([(f"g{i}", f"v{i}")]) for i, name in enumerate(names)}
    for name in names:
        ctx.on_cleanup(lambda n=name: _safe_delete_lexicon(polly, n))

    def _put(name: str) -> None:
        polly.put_lexicon(Name=name, Content=contents[name])

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_put, name) for name in names]
        for fut in as_completed(futures):
            fut.result()

    for name in names:
        got = polly.get_lexicon(Name=name)
        assert got["Lexicon"]["Name"] == name, (
            f"expected lexicon name {name!r}, got {got['Lexicon']['Name']!r}"
        )
        assert got["Lexicon"]["Content"] == contents[name], (
            f"lexicon {name!r} content diverged from what this racer wrote -- "
            f"expected={contents[name]!r} got={got['Lexicon']['Content']!r}"
        )
        assert got["LexiconAttributes"]["LexemesCount"] == 1, (
            f"lexicon {name!r} expected exactly 1 lexeme, "
            f"got {got['LexiconAttributes']['LexemesCount']}"
        )


def _lexicon_name(ctx, tag: str) -> str:
    # Lexicon names are [0-9A-Za-z]{1,20}; "sim2real" (8) + the 12-hex unique suffix is exactly 20,
    # so `tag` no longer fits without truncating the random suffix. It stays a call-site label only.
    raw = ctx.unique_name("sim2real")
    return "".join(ch for ch in raw if ch.isalnum())[:20]


def _pls(entries, lang: str = "en-US", alphabet: str = "ipa") -> str:
    body = "".join(
        f"<lexeme><grapheme>{g}</grapheme><alias>{a}</alias></lexeme>"
        for g, a in entries
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon" '
        f'alphabet="{alphabet}" xml:lang="{lang}">{body}</lexicon>'
    )


def _safe_delete_lexicon(polly, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        polly.delete_lexicon(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LexiconNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
