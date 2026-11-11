"""assume-role-session-policy-cannot-exceed-role-permissions-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-policy-cannot-exceed-role-permissions-denied"
GROUP = "overly-permissive"
SERVICES = ["sts"]
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole with an allow-all session policy succeeds, but the credentials stay bounded by
    the role's identity policy: s3:ListAllMyBuckets (granted) works, iam:ListUsers (not granted)
    is AccessDenied -- the excess is intersected away, not rejected at assume time."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    identity_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:ListAllMyBuckets", "sts:GetCallerIdentity"],
            "Resource": "*",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="perm", PolicyDocument=json.dumps(identity_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="perm"))

    # IAM role trust/identity policies are eventually consistent; warm up with a plain
    # AssumeRole (no session policy) retried until it succeeds.
    _warm_up_assume_role(ctx, role_arn)

    # Session policy tries to grant everything -- strictly more than the role's own
    # identity policy (which only allows s3:ListAllMyBuckets + sts:GetCallerIdentity).
    over_broad_session_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    # A replica that has not seen the new trust policy can still refuse the first scoped call.
    session_name = ctx.unique_name("sess-")
    creds = _warm_up_assume_role(
        ctx, role_arn,
        session_name=session_name,
        Policy=json.dumps(over_broad_session_policy),
    )

    assumed_s3 = _client_with_creds(ctx, "s3", creds)
    assumed_iam = _client_with_creds(ctx, "iam", creds)

    # Positive control: proves the credentials are live, not a session broken outright.
    _poll_until(
        lambda: _error_code(lambda: assumed_s3.list_buckets()),
        lambda code: code == _OK,
        timeout_s=20.0,
        interval_s=2.0,
    )

    # iam:ListUsers is outside the role's identity policy, so the session's "*" cannot grant it.
    code, message = _error(lambda: assumed_iam.list_users())
    allowed_codes = ("AccessDenied",)
    msg = "code=%r" % code
    assert code in allowed_codes, msg
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not authorized "
        f"to perform: iam:ListUsers on resource: arn:aws:iam::{account_id}:user/ because no "
        "identity-based policy allows the iam:ListUsers action"
    ), message


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _error_code(fn):
    return _error(fn)[0]


def _error(fn):
    """(code, message) of the ClientError fn raises, or (_OK, None) when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _OK, None


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


def _warm_up_assume_role(
    ctx, role_arn: str, timeout_s: float = 45.0, interval_s: float = 3.0,
    session_name: str = "warmup", **kwargs,
):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, **kwargs
            )["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
