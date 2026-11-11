"""list-policies-granting-service-access."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-policies-granting-service-access"
GROUP = 'access_reports'
SERVICES = ['iam']

S3_READONLY_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"


def _error_code(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _unprivileged_client(ctx):
    """Return ``(user_name, iam client)`` for a new zero-permission user with a fresh access key.
    Polls STS until the key authenticates (new keys propagate eventually); cleanup is registered."""
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
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidClientTokenId", "InvalidAccessKeyId"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the new access key never authenticated within {budget_s:.0f}s; last {code}")
            time.sleep(3)
    return user_name, ctx.client("iam", creds=creds)


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPoliciesGrantingServiceAccess lists an attached AmazonS3ReadOnlyAccess as granting 's3';
    a nonexistent principal Arn fails NoSuchEntity and a zero-permission caller fails AccessDenied,
    each with AWS's exact message."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("lpgsa-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    iam.attach_user_policy(UserName=user_name, PolicyArn=S3_READONLY_MANAGED_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=S3_READONLY_MANAGED_POLICY_ARN)
    )
    user_arn = iam.get_user(UserName=user_name)["User"]["Arn"]

    resp = iam.list_policies_granting_service_access(
        Arn=user_arn, ServiceNamespaces=["s3"]
    )["PoliciesGrantingServiceAccess"]
    assert len(resp) == 1 and resp[0]["ServiceNamespace"] == "s3", f"unexpected shape: {resp}"
    granting_names = [p["PolicyName"] for p in resp[0]["Policies"]]
    assert "AmazonS3ReadOnlyAccess" in granting_names, (
        f"expected the attached managed policy among granting policies, got {granting_names}"
    )

    account = ctx.client("sts").get_caller_identity()["Account"]
    bad_name = ctx.unique_name("missing-")
    bad_arn = f"arn:aws:iam::{account}:user/{bad_name}"
    code, message = _error_code(
        lambda: iam.list_policies_granting_service_access(Arn=bad_arn, ServiceNamespaces=["s3"])
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent Arn, got {code}"
    expected_missing = f"ARN {bad_arn} does not exist."
    assert message == expected_missing, (
        f"the nonexistent Arn must be refused with AWS's exact message {expected_missing!r}; "
        f"got {message!r}"
    )

    unpriv_name, unpriv = _unprivileged_client(ctx)
    code2, message2 = _error_code(
        lambda: unpriv.list_policies_granting_service_access(Arn=user_arn, ServiceNamespaces=["s3"])
    )
    assert code2 == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code2}"
    expected_denied = (
        f"User: arn:aws:iam::{account}:user/{unpriv_name} is not authorized to perform: "
        f"iam:ListPoliciesGrantingServiceAccess on resource: {user_arn} because no "
        f"identity-based policy allows the iam:ListPoliciesGrantingServiceAccess action"
    )
    assert message2 == expected_denied, (
        f"the zero-permission caller's denial must carry AWS's exact message {expected_denied!r}; "
        f"got {message2!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
