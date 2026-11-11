"""concurrent-create-vocabulary-same-name-one-wins."""
from __future__ import annotations

import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "concurrent-create-vocabulary-same-name-one-wins"
GROUP = "concurrency"
SERVICES = ["transcribe"]

# Transcribe custom-vocabulary phrases reject digits; the vocabulary still gets
# created (202) but processing terminates FAILED, which the racer index alone
# would trigger for every one of the 8 racers. Letters-only, still one per racer.
# AWS's own wording for a vocabulary name conflict says "job name".
_CONFLICT_MESSAGE = "The requested job name already exists. Use a different job name."

_RACER_WORDS = ["Aardvark", "Bobcat", "Cheetah", "Dingo", "Egret", "Falcon", "Gibbon", "Heron"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """Eight concurrent CreateVocabulary calls with one name: exactly one succeeds, the others fail with
    ConflictException, and the stored vocabulary holds only the winner's phrase."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-vocab-race-")
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, name))

    def attempt(i: int) -> tuple[int, str, str | None]:
        try:
            tx.create_vocabulary(
                VocabularyName=name,
                LanguageCode="en-US",
                Phrases=[_RACER_WORDS[i]],
                Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
            )
            return (i, "success", None)
        except ClientError as e:
            return (i, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(attempt, range(8)))

    successes = [i for i, r, _ in results if r == "success"]
    conflicts = [m for _, r, m in results if r == "ConflictException"]
    assert len(successes) == 1, f"expected exactly one winner among racers, got: {results}"
    assert len(conflicts) == len(results) - 1, f"expected all losers to be ConflictException, got: {results}"
    assert all(m == _CONFLICT_MESSAGE for m in conflicts), (
        f"expected every loser's message to be {_CONFLICT_MESSAGE!r}, got: {results}"
    )
    winner = successes[0]

    # independent terminal read at the destination, through a different operation
    # than the ones that raced: the surviving content must be the WINNER's phrase,
    # and no loser's phrase must have leaked in via a lost update.
    final_state = _poll_vocabulary_state(ctx, name, timeout_s=300, interval_s=10)
    assert final_state == "READY", f"vocabulary never reached READY, last state={final_state}"
    content = _download(ctx, tx.get_vocabulary(VocabularyName=name)["DownloadUri"]).upper()
    assert _RACER_WORDS[winner].upper() in content, (
        f"winning racer {winner}'s content missing from vocabulary: {content!r}"
    )
    for i in range(8):
        if i != winner:
            assert _RACER_WORDS[i].upper() not in content, (
                f"loser racer {i}'s content leaked into the vocabulary: {content!r}"
            )


def _poll_vocabulary_state(ctx, name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = tx.get_vocabulary(VocabularyName=name)["VocabularyState"]
        if state != "PENDING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"vocabulary {name} stayed PENDING for {timeout_s}s (last state={state})")


def _download(ctx, url: str) -> str:
    with urllib.request.urlopen(_routed_request(ctx, url), timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _delete_vocabulary_ignore_missing(ctx, name: str) -> None:
    tx = ctx.client("transcribe")
    try:
        tx.delete_vocabulary(VocabularyName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "BadRequestException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
