"""delete-dictionary-referenced-by-feed-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dictionary-referenced-by-feed-rejected"
GROUP = "overly-permissive"
SERVICES = ["elementalinference"]


def _error_code(fn, within_s=0.0, interval_s=2.0):
    """Call fn() until it raises a ClientError and return its (code, message). A call that still
    SUCCEEDS once within_s has passed raises."""
    deadline = time.monotonic() + within_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _delete_dictionary_with_retry(ei, dict_id, timeout_s=90.0, interval_s=3.0):
    """Delete the dictionary, retrying while a draining reference still holds it (ConflictException).
    An already-deleted dictionary is done; any other refusal, or a conflict past timeout_s, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ei.delete_dictionary(id=dict_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_if_present(delete, resource_id):
    """Teardown delete that tolerates a resource the check body already deleted."""
    try:
        delete(id=resource_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDictionary is rejected with ConflictException while a feed still references the dictionary."""
    ei = ctx.client("elementalinference")

    dict_name = ctx.unique_name("sim2real-ei-dict-")
    dict_id = ei.create_dictionary(
        name=dict_name,
        language="eng",
        entries='[{"content": "ace"}, {"content": "rally"}]',
        tags={"Environment": "sim2real-behav"},
    )["id"]

    feed_name = ctx.unique_name("sim2real-ei-feed-")
    output = {
        "name": "sub1",
        "outputConfig": {"subtitling": {"language": "eng", "dictionary": dict_id}},
        "status": "ENABLED",
    }
    feed_id = ei.create_feed(name=feed_name, outputs=[output], tags={"Environment": "sim2real-behav"})["id"]
    # Cleanup order (LIFO): the feed-delete cleanup (registered last) runs first, draining the
    # reference; the dictionary cleanup (registered first) runs last and retries through any
    # transient REFERENCED-state ConflictException left over from the reference draining.
    ctx.on_cleanup(lambda: _delete_dictionary_with_retry(ei, dict_id))
    ctx.on_cleanup(lambda: _delete_if_present(ei.delete_feed, feed_id))

    _poll_until(lambda: ei.get_dictionary(id=dict_id), lambda r: r["status"] == "REFERENCED")

    code, message = _error_code(lambda: ei.delete_dictionary(id=dict_id))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == (
        "Cannot delete dictionary because it is referenced by 1 feed(s). Remove all references by "
        "delete or disable related feed output(s) before deleting dictionary."
    ), message

    # Effect absent: the referenced dictionary is untouched.
    still_there = ei.get_dictionary(id=dict_id)
    assert still_there["status"] == "REFERENCED"
    assert still_there["id"] == dict_id

    # Restore: remove the reference, then the identical DeleteDictionary call must now succeed —
    # proving the ConflictException above was caused by this reference, not a blanket rejection.
    ei.delete_feed(id=feed_id)
    deadline = time.monotonic() + 90.0
    while True:
        try:
            ei.delete_dictionary(id=dict_id)
            break
        except ClientError as exc:
            # Only the draining reference may still refuse it; any other code, or a conflict that
            # outlives the window, fails the check.
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)

    # Independent read confirms it is gone, and a mutation on the dead id also fails.
    gone_code, gone_message = _error_code(lambda: ei.get_dictionary(id=dict_id), within_s=90.0)
    assert gone_code == "ResourceNotFoundException", gone_code
    assert gone_message == "Resource not found", gone_message
    redelete_code, redelete_message = _error_code(lambda: ei.delete_dictionary(id=dict_id))
    assert redelete_code == "ResourceNotFoundException", f"expected ResourceNotFoundException on re-delete, got {redelete_code}"
    assert redelete_message == "Resource not found", redelete_message

    # Positive control: an unreferenced dictionary deletes cleanly from the start.
    control_name = ctx.unique_name("sim2real-ei-dict-ctl-")
    control_id = ei.create_dictionary(
        name=control_name,
        language="eng",
        entries='[{"content": "par"}]',
        tags={"Environment": "sim2real-behav"},
    )["id"]
    ei.delete_dictionary(id=control_id)
    control_deleted, control_message = _error_code(lambda: ei.get_dictionary(id=control_id), within_s=90.0)
    assert control_deleted == "ResourceNotFoundException", control_deleted
    assert control_message == "Resource not found", control_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
