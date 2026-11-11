"""get-service-last-accessed-details."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-service-last-accessed-details"
GROUP = 'access_reports'
SERVICES = ['iam']

S3_READONLY_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(ctx, fn, pred, timeout_s=90, interval_s=3):
    """Call fn() until pred(result) is truthy or timeout; return the result. Raises on timeout rather than
    returning a stale, still-pending result."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while not pred(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = fn()
    if not pred(result):
        raise AssertionError(f"condition not observed within {timeout_s}s; last saw {result!r}")
    return result


def _unprivileged_client(ctx):
    """A brand-new IAM user with ZERO attached permissions + a minted access key, returned as an
    IAM client authenticated as that user. A fresh IAM principal implicit-denies everything, so any
    call through it is expected AccessDenied. Access-key propagation is not instant, so poll STS
    until the creds are recognized. Cleanup is registered."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("nopriv-")
    iam.create_user(UserName=user_name)

    def _cleanup():
        try:
            for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_user(UserName=user_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    created = iam.create_access_key(UserName=user_name)["AccessKey"]
    creds = {
        "aws_access_key_id": created["AccessKeyId"],
        "aws_secret_access_key": created["SecretAccessKey"],
    }
    unpriv_sts = ctx.client("sts", creds=creds)
    # Bounded by the runner's remaining time, so a key that never authenticates fails here.
    budget_s = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    deadline = time.monotonic() + budget_s
    while True:
        try:
            unpriv_sts.get_caller_identity()
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in (
                "InvalidClientTokenId",
                "InvalidAccessKeyId",
            ):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"minted access key was not recognized within {budget_s:.0f}s") from exc
            time.sleep(3)
    return ctx.client("iam", creds=creds)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After GenerateServiceLastAccessedDetails completes, ServicesLastAccessed lists s3,
    reachable through the entity's attached managed policy; a never-issued JobId fails with the
    exact NoSuchEntity and a zero-permission caller with AccessDenied naming the action."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("slauser-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    iam.attach_user_policy(UserName=user_name, PolicyArn=S3_READONLY_MANAGED_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=S3_READONLY_MANAGED_POLICY_ARN)
    )
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
    namespaces = {e["ServiceNamespace"] for e in result.get("ServicesLastAccessed", [])}
    assert "s3" in namespaces, (
        f"expected 's3' among tracked services for an S3-policy-attached user, got {namespaces}"
    )

    # A JobId that doesn't exist, but preserves the real job_id's format (hyphen positions/length)
    # so it clears server-side shape validation and falls through to the actual not-found check.
    fake_job_id = "".join("0" if c.isalnum() else c for c in job_id)
    code, message = _error(lambda: iam.get_service_last_accessed_details(JobId=fake_job_id))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a never-issued JobId, got {code}"
    expected = f"Job {fake_job_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unpriv = _unprivileged_client(ctx)
    code, message = _error(lambda: unpriv.get_service_last_accessed_details(JobId=job_id))
    assert code == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code}"
    # message varies: AWS appends a per-request authorization id that no request value determines
    # The stable part that names the refused action is graded.
    assert "is not authorized to perform: iam:GetServiceLastAccessedDetails" in message, (
        f"the denial must name the refused action iam:GetServiceLastAccessedDetails; got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
