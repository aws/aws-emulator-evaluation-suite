"""e2e-assume-role-session-tag-propagates-to-resource-access."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-assume-role-session-tag-propagates-to-resource-access"
GROUP = "state-machine"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """A role's tag-gated inline policy allows a downstream resource action (here,
    assuming a SECOND role, via role chaining) only when the session tag matches;
    an explicit Deny refuses a freshly-assumed session the same action, and restoring it re-allows.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_a_name = ctx.unique_name("sim2real-behav-tagrolea-")
    trust_policy_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_a_arn = iam.create_role(
        RoleName=role_a_name, AssumeRolePolicyDocument=json.dumps(trust_policy_a)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_a_name))

    role_b_name = ctx.unique_name("sim2real-behav-tagroleb-")
    trust_policy_b = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_b_arn = iam.create_role(
        RoleName=role_b_name, AssumeRolePolicyDocument=json.dumps(trust_policy_b)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_b_name))

    policy_name = "tag-gated-assume-role-b"
    tag_gated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": role_b_arn,
                "Condition": {
                    "StringEquals": {"aws:PrincipalTag/department": "engineering"}
                },
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_a_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(tag_gated_policy),
    )
    policy_deleted = {"done": False}

    def _cleanup_policy() -> None:
        if not policy_deleted["done"]:
            _ignore_no_such_entity(
                lambda: iam.delete_role_policy(RoleName=role_a_name, PolicyName=policy_name)
            )

    ctx.on_cleanup(_cleanup_policy)

    session_tags = [{"Key": "department", "Value": "engineering"}]

    # Assume role A once and retry only the chained call: a fresh STS session takes a few
    # seconds to become consistent, and re-assuming on each retry would restart that window.
    assumed = _retry_until_success(
        lambda: sts.assume_role(
            RoleArn=role_a_arn,
            RoleSessionName="tag-gated-session",
            Tags=session_tags,
        ),
        timeout_s=90.0,
        interval_s=3.0,
    )
    creds = assumed["Credentials"]
    client = _client_with_creds(ctx, "sts", creds)

    def _chain_allowed() -> Any:
        # The gated action is a chained AssumeRole: GetCallerIdentity needs no permission, and
        # IAM calls sign as us-east-1, which a regional STS session cannot do
        # (SignatureDoesNotMatch). Raises if denied.
        return client.assume_role(RoleArn=role_b_arn, RoleSessionName="chained-session")

    chain_resp = _retry_until_success(_chain_allowed, timeout_s=90.0, interval_s=3.0)
    # Prove the chained session really is role B's, not just that assume_role did not raise.
    chained_identity = _client_with_creds(ctx, "sts", chain_resp["Credentials"]).get_caller_identity()[
        "Arn"
    ]
    assert f":assumed-role/{role_b_name}/" in chained_identity, (
        f"a tag-matching session chained into role B must read back as role B's own identity; "
        f"independent get_caller_identity returned {chained_identity!r}"
    )

    # An explicit Deny (rather than deleting the Allow) wins over any Allow, so the refusal does
    # not depend on an absence-of-Allow propagating.
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "sts:AssumeRole",
                "Resource": role_b_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_a_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(deny_policy),
    )

    assumed2 = _retry_until_success(
        lambda: sts.assume_role(
            RoleArn=role_a_arn, RoleSessionName="tag-gated-session-2", Tags=session_tags
        ),
        timeout_s=30.0,
        interval_s=3.0,
    )
    client2 = _client_with_creds(ctx, "sts", assumed2["Credentials"])

    # STS caches an Allow decision for a (target role, calling principal) pair for several
    # minutes after the grant is withdrawn, so poll for the refusal instead of asserting on the
    # first attempt.
    _SENTINEL_ALLOWED = "__allowed__"

    def _chain_attempt() -> tuple[str | None, Any]:
        try:
            return (_SENTINEL_ALLOWED, client2.assume_role(RoleArn=role_b_arn, RoleSessionName="chained-session-2"))
        except Exception as exc:  # noqa: BLE001
            return (_client_error_code(exc), exc)

    code, result = _retry_until(
        _chain_attempt,
        predicate=lambda r: r[0] != _SENTINEL_ALLOWED,
        timeout_s=650.0,
        interval_s=10.0,
    )
    assert code == "AccessDenied", (
        f"a session assumed after role A's policy was overwritten with an explicit Deny must be "
        f"refused sts:AssumeRole on role B with AccessDenied; got {code!r} ({result!r})"
    )
    message = result.response["Error"]["Message"]
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_a_name}/tag-gated-session-2 is not "
        f"authorized to perform: sts:AssumeRole on resource: {role_b_arn}"
    ), message

    # The refusal blocked the chain; it did not substitute a different identity.
    denied_identity = client2.get_caller_identity()["Arn"]
    assert f":assumed-role/{role_a_name}/" in denied_identity, (
        f"the denied session must still read back as role A's own identity; got {denied_identity!r}"
    )

    # Restoring the Allow must re-enable the identical chain, ruling out a one-way lockout.
    iam.put_role_policy(
        RoleName=role_a_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(tag_gated_policy),
    )

    def _chain_restored() -> str:
        assumed3 = sts.assume_role(
            RoleArn=role_a_arn, RoleSessionName="tag-gated-session-3", Tags=session_tags
        )
        client3 = _client_with_creds(ctx, "sts", assumed3["Credentials"])
        resp3 = client3.assume_role(RoleArn=role_b_arn, RoleSessionName="chained-session-3")
        return _client_with_creds(ctx, "sts", resp3["Credentials"]).get_caller_identity()["Arn"]

    restored_identity = _retry_until_success(_chain_restored, timeout_s=150.0, interval_s=5.0)
    assert f":assumed-role/{role_b_name}/" in restored_identity, (
        f"restoring role A's tag-gated Allow must let an identically-tagged session chain into "
        f"role B again; independent get_caller_identity on the restored chain returned "
        f"{restored_identity!r}"
    )


def _ignore_no_such_entity(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_error_code(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return None


def _client_with_creds(ctx: Any, service: str, creds: dict) -> Any:
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        },
    )


def _retry_until_success(
    fn: Callable[[], Any], *, timeout_s: float, interval_s: float
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


def _retry_until(
    fn: Callable[[], Any], *, predicate: Callable[[Any], bool], timeout_s: float, interval_s: float
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

