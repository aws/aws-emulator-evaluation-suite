"""delete-vocabulary-while-pending-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vocabulary-while-pending-rejected"
GROUP = "overly-permissive"
SERVICES = ["transcribe"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVocabulary on a vocabulary still in the PENDING (non-terminal) state is
    rejected with BadRequestException; the vocabulary must still exist afterwards, and
    deleting the SAME vocabulary succeeds once it reaches READY (positive control)."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-vocab-pending-")
    create_resp = tx.create_vocabulary(VocabularyName=name, LanguageCode="en-US", Phrases=["Alpha", "Beta", "Gamma"])
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, name))
    # AWS docs: vocabulary creation is asynchronous; a freshly created vocabulary is
    # guaranteed PENDING in the CreateVocabulary response itself (no race to poll for).
    assert create_resp["VocabularyState"] == "PENDING", (
        f"expected a freshly created vocabulary to start PENDING, got {create_resp['VocabularyState']!r}"
    )

    code, message = _client_error(lambda: tx.delete_vocabulary(VocabularyName=name))
    assert code == "BadRequestException", f"expected BadRequestException deleting a PENDING vocabulary, got {code!r}"
    expected = (
        "The vocabulary that you\u2019re trying to delete isn't in the READY or FAILED state. "
        "Try your request again when the vocabulary state is READY or FAILED."
    )
    assert message == expected, f"expected pending-delete message {expected!r}, got {message!r}"

    # effect absent: the vocabulary is still there, unaffected by the rejected delete
    still_there = tx.get_vocabulary(VocabularyName=name)
    assert still_there["VocabularyName"] == name, (
        f"expected {name!r} to still exist after the rejected delete, got {still_there['VocabularyName']!r}"
    )

    # positive control: once terminal (READY), delete succeeds for real
    final_state = _poll_vocabulary_state(ctx, name, timeout_s=300, interval_s=10)
    assert final_state == "READY", f"expected the vocabulary to reach READY, got {final_state!r}"
    tx.delete_vocabulary(VocabularyName=name)
    # empirically Transcribe reports the now-deleted resource as
    # BadRequestException, not the modeled NotFoundException -- see
    # API_GetVocabulary.html: BadRequestException "can occur when the entity
    # you're trying to delete doesn't exist"
    code_after, message_after = _client_error(lambda: tx.get_vocabulary(VocabularyName=name))
    assert code_after == "BadRequestException", (
        f"expected BadRequestException reading a deleted vocabulary, got {code_after!r}"
    )
    expected_after = (
        "The requested vocabulary couldn't be found. Check the vocabulary name and try your request again."
    )
    assert message_after == expected_after, f"expected not-found message {expected_after!r}, got {message_after!r}"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
