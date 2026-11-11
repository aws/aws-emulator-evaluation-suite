"""assume-role-expiration-is-issuance-plus-requested-duration."""
from __future__ import annotations

import email.utils
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-expiration-is-issuance-plus-requested-duration"
GROUP = "credential-issuance"
SERVICES = ["sts"]

#: AssumeRole DurationSeconds floor, and the role's MaxSessionDuration (the ceiling it allows).
_MIN_DURATION_S = 900
_ROLE_MAX_S = 3600
#: Client/server skew and request latency on a clock-based bound.
_TOLERANCE_S = 120
_SUCCEEDED = "<call succeeded>"


def _client_with_credentials(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _error_code(fn):
    """The error code of a failing call, or ``_SUCCEEDED`` when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return _SUCCEEDED


def _refusal(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected a ClientError")


def _poll(probe, predicate, *, timeout_s, description, interval_s=2.0):
    """Bounded poll to a condition; raises with the last observation at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s (last: {last!r})")
        time.sleep(interval_s)


def _server_time(response):
    """AWS's own clock when it produced ``response``, from the HTTP Date header."""
    raw = response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("date")
    assert raw, "the response carried no Date header, so its server-side instant is unknown"
    return email.utils.parsedate_to_datetime(raw)


def _delete_bucket(s3, bucket):
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_role(iam, role_name):
    for fn in (
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline"),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AssumeRole reports Expiration = issuance (the response's Date) + DurationSeconds within 120 s
    on both bounds, at the 900 s floor and at the role's MaxSessionDuration; the session performs
    the role-permitted ListBucket, and a duration above MaxSessionDuration is refused.

    Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-sts-")
    params = {"Bucket": bucket}
    # us-east-1 is S3's default region: CreateBucket rejects it as an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        MaxSessionDuration=_ROLE_MAX_S,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}"}
                ],
            }
        ),
    )

    def _assume(duration_s):
        return sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            DurationSeconds=duration_s,
        )

    def _try_assume():
        try:
            return _assume(_MIN_DURATION_S)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    # A new role's trust and identity policies propagate over seconds: wait until a session is
    # issued and can perform the granted call before any timed session is minted.
    warm = _poll(_try_assume, lambda r: isinstance(r, dict), timeout_s=240.0,
                 description="the role became assumable")
    warm_s3 = _client_with_credentials(ctx, "s3", warm["Credentials"])
    _poll(lambda: _error_code(lambda: warm_s3.list_objects_v2(Bucket=bucket, MaxKeys=1)),
          lambda c: c == _SUCCEEDED, timeout_s=240.0,
          description="the role's s3:ListBucket grant became effective")

    for duration_s in (_MIN_DURATION_S, _ROLE_MAX_S):
        resp = _assume(duration_s)
        issued_at = _server_time(resp)
        expiration = resp["Credentials"]["Expiration"]
        lifetime_s = (expiration - issued_at).total_seconds()
        assert abs(lifetime_s - duration_s) <= _TOLERANCE_S, (
            f"DurationSeconds={duration_s} must yield an Expiration {duration_s}s after issuance "
            f"(within {_TOLERANCE_S}s); got {lifetime_s:.0f}s (issued {issued_at.isoformat()}, "
            f"expires {expiration.isoformat()})"
        )
        session_s3 = _client_with_credentials(ctx, "s3", resp["Credentials"])
        listed = _poll(
            lambda s=session_s3: _error_code(lambda: s.list_objects_v2(Bucket=bucket, MaxKeys=1)),
            lambda c: c == _SUCCEEDED, timeout_s=60.0,
            description=f"the {duration_s}s session performed its permitted ListBucket",
        )
        assert listed == _SUCCEEDED, listed

    refusal = _refusal(lambda: _assume(_ROLE_MAX_S + 1))
    expected = (
        "ValidationError",
        "The requested DurationSeconds exceeds the MaxSessionDuration set for this role.",
    )
    assert refusal == expected, (
        f"DurationSeconds={_ROLE_MAX_S + 1} on a role with MaxSessionDuration={_ROLE_MAX_S}: "
        f"expected {expected!r}, got {refusal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
