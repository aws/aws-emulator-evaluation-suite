"""create-vocabulary-duplicate-name-conflict."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "create-vocabulary-duplicate-name-conflict"
GROUP = "overly-permissive"
SERVICES = ["transcribe"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A second CreateVocabulary with an existing name fails with ConflictException and its exact message, the
    original vocabulary keeps its phrase without the conflicting one, and a new name still creates."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-vocab-dup-")
    tx.create_vocabulary(VocabularyName=name, LanguageCode="en-US", Phrases=["Alderaan"],
                          Tags=[{"Key": "sim2real-env", "Value": "behavioral"}])
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, name))

    code, message = _client_error(
        lambda: tx.create_vocabulary(VocabularyName=name, LanguageCode="en-US", Phrases=["Tatooine"])
    )
    assert code == "ConflictException", f"expected ConflictException for duplicate name, got {code!r}"
    expected = "The requested vocabulary name already exists. Use a different vocabulary name."
    assert message == expected, f"expected duplicate-name message {expected!r}, got {message!r}"

    # effect absent: the original phrase content persisted, the conflicting phrases did not
    final_state = _poll_vocabulary_state(ctx, name, timeout_s=300, interval_s=10)
    assert final_state == "READY", f"expected vocabulary {name!r} to reach READY, got {final_state!r}"
    content = _download(ctx, tx.get_vocabulary(VocabularyName=name)["DownloadUri"]).upper()
    assert "ALDERAAN" in content, f"expected original phrase ALDERAAN in downloaded content, got {content!r}"
    assert "TATOOINE" not in content, "conflicting CreateVocabulary call overwrote the original content"

    # positive control: a genuinely new name creates fine
    other = ctx.unique_name("sim2real-behav-vocab-dup2-")
    tx.create_vocabulary(VocabularyName=other, LanguageCode="en-US", Phrases=["Naboo"],
                          Tags=[{"Key": "sim2real-env", "Value": "behavioral"}])
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, other))
    got_name = tx.get_vocabulary(VocabularyName=other)["VocabularyName"]
    assert got_name == other, f"expected positive-control vocabulary {other!r} to exist, got name {got_name!r}"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected CreateVocabulary to reject the duplicate name, but it succeeded and returned {result!r}"
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
