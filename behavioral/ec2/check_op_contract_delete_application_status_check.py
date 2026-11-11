"""op-contract-deleteApplicationStatusCheck."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteApplicationStatusCheck"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteApplicationStatusCheck with DryRun answers DryRunOperation (exact message); the real delete
    echoes the check ID and the check is then absent, and a repeat delete succeeds, echoes the same ID
    and leaves it absent."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_application_status_check") or not hasattr(
        ec2, "delete_application_status_check"
    ):
        raise AssertionError("installed botocore lacks application status check operations")

    check_id = ec2.create_application_status_check(Port=8080, Protocol="http", Path="/health")[
        "ApplicationStatusCheck"
    ]["ApplicationStatusCheckId"]
    ctx.on_cleanup(lambda: _safe_delete(ec2, check_id))

    # Error boundary: DryRun must short-circuit before the delete is applied.
    err = _client_error(
        lambda: ec2.delete_application_status_check(
            ApplicationStatusCheckId=check_id, DryRun=True
        )
    )
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"

    resp = ec2.delete_application_status_check(ApplicationStatusCheckId=check_id)
    got_id = resp["ApplicationStatusCheck"]["ApplicationStatusCheckId"]
    assert got_id == check_id, f"expected delete response to echo {check_id!r}, got {got_id!r}"

    # Independent read: a describe by the deleted check's ID returns an empty listing or a not-found
    # error; anything else fails.
    _assert_check_absent(ec2, check_id)

    # Deleting the now-nonexistent check again is idempotent on real AWS: it returns success
    # (echoing the same id) rather than a NotFound-style rejection. Assert that idempotent
    # contract explicitly instead of assuming a rejection.
    resp2 = ec2.delete_application_status_check(ApplicationStatusCheckId=check_id)
    got_id2 = resp2["ApplicationStatusCheck"]["ApplicationStatusCheckId"]
    assert got_id2 == check_id, f"expected idempotent delete to echo {check_id!r}, got {got_id2!r}"

    # Terminal read: independent of both delete calls, confirms the idempotent re-delete
    # did not resurrect or otherwise mutate anything.
    _assert_check_absent(ec2, check_id)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _assert_check_absent(ec2, check_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        listed = ec2.describe_application_status_checks(
            ApplicationStatusCheckIds=[check_id]
        ).get("ApplicationStatusChecks", [])
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert "NotFound" in code, f"expected a NotFound-style code for a deleted check, got {code!r}"
        return
    assert listed == [], f"expected the check to be gone, found {listed}"


def _safe_delete(ec2, check_id: str) -> None:
    try:
        ec2.delete_application_status_check(ApplicationStatusCheckId=check_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidApplicationStatusCheckId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
