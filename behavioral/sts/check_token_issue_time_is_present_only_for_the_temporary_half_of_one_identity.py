"""token-issue-time-is-present-only-for-the-temporary-half-of-one-identity."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "token-issue-time-is-present-only-for-the-temporary-half-of-one-identity"
GROUP = "overly-permissive"
SERVICES = ["sts"]

_PROPAGATION_DEADLINE_S = 240.0
# What _error_code returns when the call succeeds: equal to no AWS error code.
_SUCCEEDED = "<call succeeded>"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A `Null aws:TokenIssueTime` condition admits an IAM user's long-term key and refuses that
    same user's GetSessionToken credentials, and flipping the Null value reverses both outcomes,
    because the key is present only for temporary credentials."""
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    def _client_with_credentials(service, creds, region=None):
        return ctx.client(
            service,
            region=region,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
            },
        )

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _SUCCEEDED

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
        """Bounded poll to a condition. RAISES on deadline miss -- never a bare sleep."""
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})"
                )
            time.sleep(interval_s)

    def _poll_allowed(fn, *, timeout_s=_PROPAGATION_DEADLINE_S, what="call"):
        return _poll(
            lambda: _error_code(fn),
            lambda c: c == _SUCCEEDED,
            timeout_s=timeout_s,
            interval_s=3.0,
            description=f"{what} became permitted",
        )

    def _poll_denied(fn, expected, *, timeout_s=_PROPAGATION_DEADLINE_S, what="call"):
        """Poll until fn() fails with EXACTLY `expected`. Only ever called after a positive
        control on the same wiring has proven the read reachable, so an over-permissive target
        never reaches the condition and the deadline miss IS the verdict."""
        return _poll(
            lambda: _error_code(fn),
            lambda c: c == expected,
            timeout_s=timeout_s,
            interval_s=3.0,
            description=f"{what} became refused with {expected}",
        )

    def _tags_kv(scenario):
        return [
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": scenario},
        ]

    def _drop_user(user_name):
        for page in iam.get_paginator("list_user_policies").paginate(UserName=user_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_user_policy(UserName=user_name, PolicyName=pname)
        for page in iam.get_paginator("list_access_keys").paginate(UserName=user_name):
            for meta in page.get("AccessKeyMetadata", []):
                iam.delete_access_key(UserName=user_name, AccessKeyId=meta["AccessKeyId"])
        iam.delete_user(UserName=user_name)
        _poll(
            lambda: _error_code(lambda: iam.get_user(UserName=user_name)),
            lambda c: c == "NoSuchEntity",
            timeout_s=90.0,
            interval_s=2.0,
            description=f"user {user_name} disappeared",
        )

    def _drop_bucket(bucket):
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
        _poll(
            lambda: _error_code(lambda: s3.head_bucket(Bucket=bucket)),
            lambda code: code in {"404", "NoSuchBucket"},
            timeout_s=90.0,
            interval_s=2.0,
            description=f"bucket {bucket} disappeared",
        )

    def _new_bucket(scenario):
        bucket = ctx.unique_name("sim2real-behav-sts-")
        params = {"Bucket": bucket}
        if ctx.region and ctx.region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
        s3.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(bucket))
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for
        # credentials whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(
            lambda: _error_code(lambda: probe.get_caller_identity()),
            lambda c: c == _SUCCEEDED,
            timeout_s=180.0,
            interval_s=2.0,
            description="credentials became active",
        )

    scenario = "sts-token-issue-time-presence"
    bucket = _new_bucket(scenario)
    key = "token-issue-time"
    payload = b"is-the-token-issue-time-key-in-the-request-context"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    object_arn = f"arn:aws:s3:::{bucket}/{key}"

    user_name = ctx.unique_name("sim2real-behav-tit-")
    iam.create_user(UserName=user_name, Tags=_tags_kv(scenario))
    ctx.on_cleanup(lambda: _drop_user(user_name))
    policy_name = "token-issue-time-gate"

    def _put_user_policy(null_value):
        """The user's ONLY Allow, gated on whether aws:TokenIssueTime is absent ("true") or
        present ("false"); sts:GetSessionToken is granted unconditionally either way."""
        iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": object_arn,
                            "Condition": {"Null": {"aws:TokenIssueTime": null_value}},
                        },
                        {
                            "Effect": "Allow",
                            "Action": "sts:GetSessionToken",
                            "Resource": "*",
                        },
                    ],
                }
            ),
        )

    # Gate pointing at absent: only long-term credentials may read.
    _put_user_policy("true")
    long_term = iam.create_access_key(UserName=user_name)["AccessKey"]
    _wait_creds_active(long_term)
    long_term_s3 = _client_with_credentials("s3", long_term)
    long_term_sts = _client_with_credentials("sts", long_term)

    def _long_term_read():
        return long_term_s3.get_object(Bucket=bucket, Key=key)

    # Positive control and propagation barrier: the long-term key reads because
    # aws:TokenIssueTime is absent for it.
    _poll_allowed(
        _long_term_read,
        what=f"long-term key of {user_name} GetObject under Null aws:TokenIssueTime=true",
    )
    control_bytes = _long_term_read()["Body"].read()
    assert control_bytes == payload, (
        f"positive control read wrong bytes from s3://{bucket}/{key}: expected {payload!r}, "
        f"got {control_bytes!r}"
    )

    session_creds = long_term_sts.get_session_token(DurationSeconds=900)["Credentials"]
    _wait_creds_active(session_creds)
    session_s3 = _client_with_credentials("s3", session_creds)
    session_sts = _client_with_credentials("sts", session_creds)

    def _session_read():
        return session_s3.get_object(Bucket=bucket, Key=key)

    # Both callers must be the same principal, so only temporariness explains the outcomes.
    long_term_identity = long_term_sts.get_caller_identity()
    session_identity = session_sts.get_caller_identity()
    account = sts.get_caller_identity()["Account"]
    assert long_term_identity["Account"] == account, (
        f"the IAM user this check created does not resolve to the account the harness is leased: "
        f"expected {account!r}, got {long_term_identity['Account']!r}"
    )
    assert session_identity["Arn"] == long_term_identity["Arn"], (
        f"GetSessionToken changed the caller arn, so the two halves are not one identity: "
        f"long-term {long_term_identity['Arn']!r} vs session {session_identity['Arn']!r}"
    )
    assert session_identity["UserId"] == long_term_identity["UserId"], (
        f"GetSessionToken changed aws:userid, so the two halves are not one identity: "
        f"long-term {long_term_identity['UserId']!r} vs session {session_identity['UserId']!r}"
    )
    assert session_creds.get("SessionToken"), (
        "GetSessionToken returned credentials with no SessionToken, so there is no temporary half "
        "to compare against"
    )

    # The same policy that admitted the long-term key refuses the temporary credentials.
    _poll_denied(
        _session_read,
        "AccessDenied",
        what=(
            f"GetSessionToken credentials of {user_name} GetObject under "
            f"Null aws:TokenIssueTime=true"
        ),
    )

    # The refusal also holds through a different operation on the same object.
    try:
        session_s3.head_object(Bucket=bucket, Key=key)
        head_code, head_message = _SUCCEEDED, None
    except ClientError as exc:
        head_code = exc.response.get("Error", {}).get("Code")
        head_message = exc.response.get("Error", {}).get("Message")
    # A HEAD refusal carries no body; botocore reports the status and its reason phrase.
    assert head_code == "403", (
        f"HeadObject on s3://{bucket}/{key} was not refused for the temporary credentials while "
        f"the only Allow required aws:TokenIssueTime to be absent: expected 403, got {head_code!r}"
    )
    assert head_message == "Forbidden", head_message

    _put_user_policy("false")

    _poll_allowed(
        _session_read,
        what=(
            f"GetSessionToken credentials of {user_name} GetObject under "
            f"Null aws:TokenIssueTime=false"
        ),
    )
    # The long-term key is now refused, so the flip was evaluated, not merely more permissive.
    _poll_denied(
        _long_term_read,
        "AccessDenied",
        what=f"long-term key of {user_name} GetObject under Null aws:TokenIssueTime=false",
    )

    terminal = _session_read()["Body"].read()
    assert terminal == payload, (
        f"the temporary credentials read the wrong bytes from s3://{bucket}/{key} once the gate "
        f"required aws:TokenIssueTime to be present: expected {payload!r}, got {terminal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
