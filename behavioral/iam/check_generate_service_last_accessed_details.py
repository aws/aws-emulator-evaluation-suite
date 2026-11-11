"""generate-service-last-accessed-details."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-service-last-accessed-details"
GROUP = 'access_reports'
SERVICES = ['iam']


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error(fn):
    """Call fn(); return the botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(ctx, fn, pred, timeout_s=90, interval_s=3):
    """Call fn() until pred(result) is truthy; raise on timeout rather than returning the last
    (non-terminal) value."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while not pred(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not observed within {timeout_s}s; last saw {result!r}")
        time.sleep(interval_s)
        result = fn()
    return result


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GenerateServiceLastAccessedDetails on a real user ARN starts a job that polls through to
    COMPLETED via GetServiceLastAccessedDetails; a nonexistent Arn is rejected NoSuchEntity."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("svcuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    user_arn = iam.get_user(UserName=user_name)["User"]["Arn"]

    job_id = iam.generate_service_last_accessed_details(Arn=user_arn)["JobId"]

    result = _poll_until(
        ctx,
        lambda: iam.get_service_last_accessed_details(JobId=job_id),
        lambda r: r.get("JobStatus") in ("COMPLETED", "FAILED"),
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
    )
    assert result["JobStatus"] == "COMPLETED", f"expected COMPLETED, got {result}"

    # Error boundary: Arn that doesn't (and never did) exist.
    account = ctx.client("sts").get_caller_identity()["Account"]
    bad_arn = f"arn:aws:iam::{account}:user/{ctx.unique_name('missing-')}"
    code, message = _error(lambda: iam.generate_service_last_accessed_details(Arn=bad_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent Arn, got {code}"
    expected_message = f"ARN {bad_arn} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
