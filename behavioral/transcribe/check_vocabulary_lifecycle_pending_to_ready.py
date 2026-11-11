"""vocabulary-lifecycle-pending-to-ready."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vocabulary-lifecycle-pending-to-ready"
GROUP = "state"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVocabulary starts PENDING and transitions to READY (VocabularyState state machine)."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-vocab-")
    create_resp = tx.create_vocabulary(
        VocabularyName=name,
        LanguageCode="en-US",
        Phrases=["Colorado", "Utah", "Nevada"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, name))

    # The create response itself is a synchronous contract: a brand new vocabulary
    # always starts in PENDING while Transcribe processes the phrase list.
    assert create_resp["VocabularyState"] == "PENDING", (
        f"expected PENDING on create, got {create_resp['VocabularyState']}"
    )

    final_state = _poll_vocabulary_state(ctx, name, timeout_s=300, interval_s=10)
    assert final_state == "READY", f"expected READY, got {final_state}"


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
