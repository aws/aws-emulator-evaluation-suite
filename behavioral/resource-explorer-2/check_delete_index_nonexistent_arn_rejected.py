"""delete-index-nonexistent-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-index-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-explorer-2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """DeleteIndex on a well-formed but nonexistent index ARN is rejected with
    ResourceNotFoundException, the real index in the Region is left untouched, and deleting the
    real index by its actual ARN still succeeds."""
    rex = ctx.client("resource-explorer-2")
    real_arn = _create_index_and_wait_active(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:resource-explorer-2:{ctx.region}:{account_id}:index/00000000-0000-0000-0000-000000000000"

    code = _error_code(lambda: rex.delete_index(Arn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected DeleteIndex on a nonexistent ARN to be rejected with ResourceNotFoundException, got {code!r}"

    # effect absent: the real index is still active, unaffected by the rejected bogus delete
    state_after_bogus = rex.get_index()["State"]
    assert state_after_bogus == "ACTIVE", f"expected the real index to remain ACTIVE after the rejected bogus delete, got {state_after_bogus!r}"
    arn_after_bogus = rex.get_index()["Arn"]
    assert arn_after_bogus == real_arn, f"expected the real index ARN to be unchanged, expected {real_arn!r} got {arn_after_bogus!r}"

    # positive control: deleting the real index by its actual ARN succeeds
    deleted = rex.delete_index(Arn=real_arn)
    assert deleted["Arn"] == real_arn, f"expected DeleteIndex to echo the real ARN {real_arn!r}, got {deleted.get('Arn')!r}"
    assert deleted["State"] in ("DELETING", "DELETED"), f"expected DeleteIndex to report DELETING/DELETED, got {deleted.get('State')!r}"

    # terminal read: independent of the mutating DeleteIndex call itself. GetIndex either 404s with
    # ResourceNotFoundException or settles into the terminal DELETED state -- both are observed
    # real-AWS outcomes for this transition.
    outcome = _poll_index_gone(ctx)
    assert outcome in ("GONE", "DELETED"), f"expected an independent GetIndex read to report the deleted index gone or DELETED, got {outcome!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


def _create_index_and_wait_active(ctx) -> str:
    rex = ctx.client("resource-explorer-2")
    arn = rex.create_index(Tags={"sim2real:managed": "true"})["Arn"]

    def _cleanup() -> None:
        try:
            rex.delete_index(Arn=arn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # the run already deleted the index: a re-delete of a DELETED index is a ValidationException
            if code == "ValidationException" and _poll_index_gone(ctx) in ("GONE", "DELETED"):
                return
            raise
        _poll_index_gone(ctx)

    ctx.on_cleanup(_cleanup)
    _poll_until(lambda: rex.get_index()["State"], lambda s: s == "ACTIVE", timeout_s=90.0, interval_s=3.0)
    return arn


def _poll_index_gone(ctx, timeout_s=90.0, interval_s=3.0) -> str:
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")

    def _probe():
        try:
            return rex.get_index()["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "GONE"
            raise

    return _poll_until(_probe, lambda s: s in ("GONE", "DELETED"), timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
