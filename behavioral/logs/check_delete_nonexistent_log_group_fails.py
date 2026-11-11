"""delete-nonexistent-log-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _ignore_not_found(fn):
    """Teardown helper: a resource the check already deleted is not a teardown failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

CHECK = "delete-nonexistent-log-group-fails"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLogGroup removes an existing group, and on a never-created group raises ResourceNotFoundException
    with its exact message.
    """
    svc = ctx.client("logs")

    control_name = ctx.unique_name("sim2real-behav-lg-control-")
    svc.create_log_group(logGroupName=control_name)
    ctx.on_cleanup(lambda _n=control_name: _ignore_not_found(lambda: svc.delete_log_group(logGroupName=_n)))
    svc.delete_log_group(logGroupName=control_name)
    resp = svc.describe_log_groups(logGroupNamePrefix=control_name)
    assert not any(g["logGroupName"] == control_name for g in resp.get("logGroups", [])), (
        f"control log group {control_name} still present after delete"
    )

    missing_name = ctx.unique_name("sim2real-behav-lg-missing-")
    error = _expect_error(lambda: svc.delete_log_group(logGroupName=missing_name))
    assert error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error!r}"
    expected_message = "The specified log group does not exist."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
