"""tightening-the-trust-policy-does-not-invalidate-an-already-vended-session."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tightening-the-trust-policy-does-not-invalidate-an-already-vended-session"
GROUP = "credential-issuance"
SERVICES = ["sts"]

# AWS caches an ALLOW decision for a (role, caller) pair for ~5 minutes: after a trust policy is
# tightened, AssumeRole keeps succeeding for ~300s even though GetRole returns the new document.
_CACHE_DEADLINE_S = 600.0
_DOCUMENT_DEADLINE_S = 60.0
_FREEZE_READS = 3
# What _error_code returns when the call succeeds; equal to no AWS error code.
_SUCCEEDED = "<call succeeded>"


# timing:real-time — ttl: 300 s
@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Tightening a role's trust policy makes AssumeRole fail with AccessDenied and the exact message,
    while a session vended before the edit keeps the same identity and still reads its S3 object.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html"""
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
        """Bounded poll to a condition; raises on deadline miss."""
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

    def _poll_allowed(fn, *, timeout_s=240.0, what="call"):
        return _poll(
            lambda: _error_code(fn),
            lambda c: c == _SUCCEEDED,
            timeout_s=timeout_s,
            interval_s=3.0,
            description=f"{what} became permitted",
        )

    def _tags_kv(scenario):
        return [
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": scenario},
        ]

    account = sts.get_caller_identity()["Account"]

    def _trust(principal_arn, condition=None):
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": principal_arn},
            "Action": ["sts:AssumeRole"],
        }
        if condition is not None:
            stmt["Condition"] = condition
        return {"Version": "2012-10-17", "Statement": [stmt]}

    def _drop_role(role_name):
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
        _poll(
            lambda: _error_code(lambda: iam.get_role(RoleName=role_name)),
            lambda c: c == "NoSuchEntity",
            timeout_s=90.0,
            interval_s=2.0,
            description=f"role {role_name} disappeared",
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

    refusal = {}

    def _try_assume(client, role_arn, session_name):
        """The AssumeRole response on success, or the error code string on failure (its message
        kept in ``refusal``)."""
        try:
            return client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        except ClientError as exc:
            refusal["message"] = exc.response.get("Error", {}).get("Message")
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, session_name):
        return _poll(
            lambda: _try_assume(client, role_arn, session_name),
            lambda r: isinstance(r, dict),
            timeout_s=240.0,
            interval_s=3.0,
            description=f"role {role_arn} became assumable",
        )

    def _wait_creds_active(creds):
        probe = _client_with_credentials("sts", creds)
        _poll(
            lambda: _error_code(lambda: probe.get_caller_identity()),
            lambda c: c == _SUCCEEDED,
            timeout_s=180.0,
            interval_s=2.0,
            description="temporary credentials became active",
        )

    scenario = "sts-trust-tighten-spares-live-session"
    bucket = _new_bucket(scenario)
    key = "live-session-survives"
    payload = b"a-trust-policy-is-an-assumption-time-gate"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    object_arn = f"arn:aws:s3:::{bucket}/{key}"

    role_name = ctx.unique_name("sim2real-behav-tighten-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust(f"arn:aws:iam::{account}:root")),
        MaxSessionDuration=3600,
        Tags=_tags_kv(scenario),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="read-the-object",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": object_arn}
                ],
            }
        ),
    )

    session_name = ctx.unique_name("sim2real-behav-sess-")
    creds = _wait_assumable(sts, role_arn, session_name)["Credentials"]
    _wait_creds_active(creds)
    sess_s3 = _client_with_credentials("s3", creds)
    sess_sts = _client_with_credentials("sts", creds)

    def _read():
        return sess_s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    _poll_allowed(
        lambda: sess_s3.get_object(Bucket=bucket, Key=key),
        what="the vended session's GetObject before the tightening",
    )
    before_bytes = _read()
    assert before_bytes == payload, (
        f"positive control read wrong bytes from s3://{bucket}/{key}: expected {payload!r}, "
        f"got {before_bytes!r}"
    )
    session_arn = sess_sts.get_caller_identity()["Arn"]
    assert session_arn.startswith(f"arn:aws:sts::{account}:assumed-role/{role_name}/"), (
        f"the vended session does not present as a session of {role_name}: got {session_arn!r}"
    )

    # IAM refuses a Principal naming a nonexistent entity ("Invalid principal in policy"), but a
    # Condition value is a plain string, so the unmatchable ARN goes in aws:PrincipalArn instead.
    unmatchable_arn = f"arn:aws:iam::{account}:user/{ctx.unique_name('sim2real-behav-nobody-')}"
    iam.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(
            _trust(
                f"arn:aws:iam::{account}:root",
                condition={"StringEquals": {"aws:PrincipalArn": unmatchable_arn}},
            )
        ),
    )

    stored = _poll(
        lambda: iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"],
        lambda doc: json.dumps(doc).find(unmatchable_arn) != -1,
        timeout_s=_DOCUMENT_DEADLINE_S,
        interval_s=2.0,
        description="GetRole reflected the tightened AssumeRolePolicyDocument",
    )
    stored_conditions = [
        s.get("Condition", {}).get("StringEquals", {}).get("aws:PrincipalArn")
        for s in stored["Statement"]
    ]
    assert stored_conditions == [unmatchable_arn], (
        f"GetRole's stored trust policy names the wrong condition principal after the tightening: "
        f"expected [{unmatchable_arn!r}], got {stored_conditions!r}"
    )

    # The deadline outlasts the ~300s STS decision cache.
    refused = _poll(
        lambda: _try_assume(sts, role_arn, ctx.unique_name("sim2real-behav-sess-")),
        lambda r: r == "AccessDenied",
        timeout_s=_CACHE_DEADLINE_S,
        interval_s=5.0,
        description=f"AssumeRole on {role_arn} began returning AccessDenied",
    )
    assert refused == "AccessDenied", (
        f"expected AssumeRole to be refused with AccessDenied once the trust policy named only "
        f"{unmatchable_arn}, got {refused!r}"
    )
    caller_arn = sts.get_caller_identity()["Arn"]
    denied_message = f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"
    assert refusal["message"] == denied_message, (
        f"expected message {denied_message!r}, got {refusal['message']!r}"
    )

    # Several reads, so a lazy invalidation on a later call is caught too.
    for attempt in range(_FREEZE_READS):
        after_bytes = _read()
        assert after_bytes == payload, (
            f"read {attempt + 1} of {_FREEZE_READS} by the already-vended session returned the "
            f"wrong bytes from s3://{bucket}/{key} after the trust policy was tightened: "
            f"expected {payload!r}, got {after_bytes!r} -- a trust policy governs ASSUMPTION, not "
            f"the calls of a session that was already issued"
        )

    after_arn = sess_sts.get_caller_identity()["Arn"]
    assert after_arn == session_arn, (
        f"the already-vended session's identity changed after the trust policy was tightened: "
        f"expected {session_arn!r}, got {after_arn!r}"
    )

    still_refused = _try_assume(sts, role_arn, ctx.unique_name("sim2real-behav-sess-"))
    assert still_refused == "AccessDenied", (
        f"AssumeRole stopped being refused again at the end of the check, so the two halves were "
        f"not observed in the same state: expected AccessDenied, got {still_refused!r}"
    )
    assert refusal["message"] == denied_message, (
        f"expected message {denied_message!r}, got {refusal['message']!r}"
    )
    terminal = _read()
    assert terminal == payload, (
        f"the already-vended session could not read s3://{bucket}/{key} while AssumeRole on its "
        f"own role was refused: expected {payload!r}, got {terminal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
