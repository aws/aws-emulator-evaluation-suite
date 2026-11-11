"""get-service-last-accessed-details-with-entities."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-service-last-accessed-details-with-entities"
GROUP = 'access_reports'
SERVICES = ['iam']

S3_READONLY_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises, because a target ACCEPTING input real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(fn, pred, timeout_s=90, interval_s=3):
    """Call fn() until pred(result) is truthy; raise on timeout rather than returning a stale
    result."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while not pred(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = fn()
    if not pred(result):
        raise AssertionError(f"condition not observed within {timeout_s}s; last saw {result!r}")
    return result


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetServiceLastAccessedDetailsWithEntities returns an EntityDetailsList for s3 and an empty
    one for never-accessed lambda; an unknown namespace is InvalidInput and an unissued JobId
    NoSuchEntity."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-slaeuser-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    iam.attach_user_policy(UserName=user_name, PolicyArn=S3_READONLY_MANAGED_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=S3_READONLY_MANAGED_POLICY_ARN)
    )
    user_arn = iam.get_user(UserName=user_name)["User"]["Arn"]

    job_id = iam.generate_service_last_accessed_details(Arn=user_arn)["JobId"]

    _poll_until(
        lambda: iam.get_service_last_accessed_details(JobId=job_id),
        lambda r: r.get("JobStatus") in ("COMPLETED", "FAILED"),
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
    )

    ok = iam.get_service_last_accessed_details_with_entities(JobId=job_id, ServiceNamespace="s3")
    assert ok["JobStatus"] == "COMPLETED", f"expected COMPLETED, got {ok}"
    assert "EntityDetailsList" in ok, f"missing EntityDetailsList: {ok}"

    # A ServiceNamespace that isn't part of the job's tracked services still succeeds -- IAM returns
    # an empty EntityDetailsList for a namespace it never observed access to, rather than erroring.
    not_accessed = iam.get_service_last_accessed_details_with_entities(
        JobId=job_id, ServiceNamespace="lambda"
    )
    assert not_accessed["EntityDetailsList"] == [], (
        f"expected an empty EntityDetailsList for a namespace never accessed, got {not_accessed}"
    )

    # A JobId that doesn't exist but preserves the real job_id's format so it clears server-side
    # shape validation and falls through to the actual not-found check.
    fake_job_id = "".join("0" if c.isalnum() else c for c in job_id)
    code, message = _error(
        lambda: iam.get_service_last_accessed_details_with_entities(
            JobId=fake_job_id, ServiceNamespace="s3"
        )
    )
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity for a never-issued JobId, got {code}: {message!r}"
    )
    expected = f"Job {fake_job_id} does not exist."
    assert message == expected, f"NoSuchEntity message: expected {expected!r}, got {message!r}"

    bad_namespace = "not-a-real-aws-service-namespace"
    code2, message2 = _error(
        lambda: iam.get_service_last_accessed_details_with_entities(
            JobId=job_id, ServiceNamespace=bad_namespace
        )
    )
    assert code2 == "InvalidInput", (
        f"expected InvalidInput for a ServiceNamespace that isn't a real AWS service, got {code2}: "
        f"{message2!r}"
    )
    expected2 = f"Service namepace {bad_namespace} is either invalid or unsupported."
    assert message2 == expected2, f"InvalidInput message: expected {expected2!r}, got {message2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
