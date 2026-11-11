"""assume-role-session-tag-unicode-value-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["sts"]
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-byte unicode session tag value survives AssumeRole unchanged: an exact-match
    ``aws:PrincipalTag/<key>`` condition allows it and denies an ASCII look-alike, and
    GetCallerIdentity through the session reports the session's own ARN."""
    tag_key = "sim2real-unicode-tag"
    expected_value = "caf\u00e9-\u65e5\u672c\u8a9e-\u03a9"  # "café-日本語-Ω"
    identity_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:ListAllMyBuckets",
            "Resource": "*",
            "Condition": {"StringEquals": {f"aws:PrincipalTag/{tag_key}": expected_value}},
        }],
    }
    role_name, role_arn = _create_assumable_role(ctx, identity_policy)
    _warm_up_assume_role(ctx, role_arn)

    sts = ctx.client("sts")

    # Exact unicode value round-trips through the tag and satisfies the condition.
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sess-unicode-"),
        Tags=[{"Key": tag_key, "Value": expected_value}],
    )
    creds = resp["Credentials"]
    s3_client = _client_with_creds(ctx, "s3", creds)
    _poll_until(
        lambda: _error(lambda: s3_client.list_buckets())[0],
        lambda code: code == _OK,
        timeout_s=20.0,
        interval_s=2.0,
    )

    identity = _client_with_creds(ctx, "sts", creds).get_caller_identity()
    assert identity["Arn"] == resp["AssumedRoleUser"]["Arn"], (
        f"GetCallerIdentity through the session reported {identity['Arn']!r}, expected it to "
        f"match the session's own AssumedRoleUser.Arn {resp['AssumedRoleUser']['Arn']!r}"
    )

    # A different (ASCII, non-matching) tag value on a fresh session over the same
    # already-warmed-up role must NOT satisfy the exact-unicode condition.
    resp_mismatch = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sess-mismatch-"),
        Tags=[{"Key": tag_key, "Value": "cafe-nihongo-omega"}],
    )
    s3_mismatch = _client_with_creds(ctx, "s3", resp_mismatch["Credentials"])
    code, message = _error(lambda: s3_mismatch.list_buckets())
    assert code == "AccessDenied", (
        f"a session tag value that does not match the policy condition's exact unicode "
        f"string must deny s3:ListAllMyBuckets with AccessDenied; got {code!r}"
    )
    expected = _list_buckets_denied_message(resp_mismatch["AssumedRoleUser"]["Arn"])
    assert message == expected, f"expected {expected!r}, got {message!r}"


def _create_assumable_role(ctx, identity_policy_document):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="perm", PolicyDocument=json.dumps(identity_policy_document)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="perm"))
    return role_name, role_arn


def _warm_up_assume_role(ctx, role_arn: str, timeout_s: float = 45.0, interval_s: float = 3.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="warmup")["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc}")


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _error(fn):
    """``(code, message)`` of the error ``fn()`` raises, or ``(_OK, None)`` when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _OK, None


def _list_buckets_denied_message(session_arn: str) -> str:
    return (
        f"User: {session_arn} is not authorized to perform: s3:ListAllMyBuckets because no "
        "identity-based policy allows the s3:ListAllMyBuckets action"
    )


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if not predicate(last):
        raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
