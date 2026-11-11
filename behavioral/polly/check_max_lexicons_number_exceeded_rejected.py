"""max-lexicons-number-exceeded-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "max-lexicons-number-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]

_PLS = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>q</grapheme><alias>quota</alias></lexeme>
</lexicon>
"""

_DEFAULT_MAX_LEXICONS = 100  # "Default lexicon count" quota: 100 per account per region
#: Refusals read back below the quota, and freed slots lost to another run, tolerated before failing.
_QUOTA_REARMS = 3
#: Longest wait for a free slot to seed this run's own lexicon in an account another run holds full.
_SEED_WAIT_S = 180.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """At the per-region lexicon quota (100), PutLexicon fails with
    MaxLexiconsNumberExceededException and stores nothing; after one DeleteLexicon frees a slot,
    a new PutLexicon succeeds."""
    polly = ctx.client("polly")
    created: list[str] = []

    def _cleanup() -> None:
        for name in created:
            try:
                polly.delete_lexicon(Name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LexiconNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    # The positive control frees one of this run's own lexicons, so the run seeds one first. An
    # account another run holds at the quota frees slots as that run cleans up, so the seed waits
    # for one, bounded.
    seed = _lexicon_name(ctx, "seed")
    left = ctx.time_left()
    seed_deadline = time.monotonic() + (_SEED_WAIT_S if left is None else min(_SEED_WAIT_S, max(0.0, left - 120.0)))
    while True:
        try:
            polly.put_lexicon(Name=seed, Content=_PLS)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "MaxLexiconsNumberExceededException" or time.monotonic() >= seed_deadline:
                raise
            time.sleep(5)
    created.append(seed)

    # Fill the account to the quota and take the first refusal; the account's lexicon count read
    # right after it proves the refusal came at the quota. Other runs in the same account may
    # create or delete lexicons meanwhile, so a refusal read back below the quota (a slot freed
    # after it) resumes the fill, up to a bounded number of refusals.
    code = message = None
    refused_names: list[str] = []
    counts_at_refusal = []
    for i in range(_DEFAULT_MAX_LEXICONS + _QUOTA_REARMS):
        name = _lexicon_name(ctx, f"q{i}")
        try:
            polly.put_lexicon(Name=name, Content=_PLS)
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
            refused_names.append(name)
            if code != "MaxLexiconsNumberExceededException":
                break
            held = len(_list_lexicon_names(polly))
            counts_at_refusal.append(held)
            if held >= _DEFAULT_MAX_LEXICONS or len(counts_at_refusal) >= _QUOTA_REARMS:
                break
            continue
        created.append(name)
    assert code == "MaxLexiconsNumberExceededException", (
        f"expected quota rejection once the account held {_DEFAULT_MAX_LEXICONS} lexicons, got code={code}"
    )
    assert message == "Max lexicon number has been exceeded", message
    assert counts_at_refusal[-1] == _DEFAULT_MAX_LEXICONS, (
        f"expected PutLexicon to be refused only at {_DEFAULT_MAX_LEXICONS} lexicons; "
        f"the account held {counts_at_refusal} right after each refusal"
    )

    # effect absent: no refused lexicon was persisted
    names = _list_lexicon_names(polly)
    persisted = sorted(n for n in refused_names if n in names)
    assert not persisted, (
        f"rejected lexicons {persisted!r} were persisted anyway; list_lexicons={sorted(names)}"
    )

    # positive control: freeing one slot lets a new lexicon be created. A slot another run takes
    # between the delete and the put is freed again from this run's own lexicons, a bounded number
    # of times.
    assert created, "no lexicon was created to free up for the control"
    control_name = _lexicon_name(ctx, "ctl")
    for attempt in range(_QUOTA_REARMS):
        freed_name = created.pop()
        polly.delete_lexicon(Name=freed_name)
        freed_names = _list_lexicon_names(polly)
        assert freed_name not in freed_names, (
            f"deleted lexicon {freed_name!r} still listed after delete: {sorted(freed_names)}"
        )
        try:
            polly.put_lexicon(Name=control_name, Content=_PLS)
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "MaxLexiconsNumberExceededException"
                or attempt + 1 >= _QUOTA_REARMS
                or not created
            ):
                raise
    created.append(control_name)
    got_name = polly.get_lexicon(Name=control_name)["Lexicon"]["Name"]
    assert got_name == control_name, (
        f"expected freed-slot lexicon {control_name!r} to be gettable, got name={got_name!r}"
    )


def _list_lexicon_names(polly) -> set:
    """Every lexicon name ListLexicons returns, across all pages."""
    names, token = set(), None
    while True:
        page = polly.list_lexicons(**({"NextToken": token} if token else {}))
        names.update(e["Name"] for e in page["Lexicons"])
        token = page.get("NextToken")
        if not token:
            return names


def _lexicon_name(ctx: Any, tag: str = "") -> str:
    raw = ctx.unique_name(f"l{tag}")
    cleaned = "".join(c for c in raw if c.isalnum())
    return cleaned[:20] or f"lex{tag}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
