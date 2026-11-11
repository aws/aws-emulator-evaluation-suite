"""principal-arn-condition-resolves-to-the-role-arn-not-the-session-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "principal-arn-condition-resolves-to-the-role-arn-not-the-session-arn"
GROUP = "overly-permissive"
SERVICES = ["sts"]

# What _outcome returns for a call that succeeded: an object no error code can equal.
_SUCCEEDED = object()

_POLICY_DEADLINE_S = 240.0


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """For an AssumeRole session `aws:PrincipalArn` is the ROLE arn, not the session arn that
    GetCallerIdentity reports: an Allow conditioned on the session arn refuses GetObject and
    HeadObject, and the same Allow conditioned on the role arn grants GetObject again.
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # ===== helpers =====
    # _client_with_credentials signs as another identity through ctx.client, so the second hop
    # reaches whatever target ctx is pointed at.
    def _client_with_credentials(service, creds, region=None):
        return ctx.client(service, region=region, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _outcome(fn):
        """The error CODE of a failing call, or _SUCCEEDED -- an object no code can equal -- if
        it succeeded. Polls wait on it in both directions."""
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _SUCCEEDED

    def _error_code(fn):
        """The error CODE of a call that must be refused; raises when it SUCCEEDS."""
        got = _outcome(fn)
        if got is _SUCCEEDED:
            raise AssertionError("expected the call to be refused, but it SUCCEEDED")
        return got

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

    def _poll_allowed(fn, *, timeout_s=_POLICY_DEADLINE_S, what="call"):
        return _poll(
            lambda: _outcome(fn),
            lambda c: c is _SUCCEEDED,
            timeout_s=timeout_s,
            interval_s=3.0,
            description=f"{what} became permitted",
        )

    def _poll_denied(fn, expected, *, timeout_s=_POLICY_DEADLINE_S, what="call"):
        """Poll until fn() fails with EXACTLY `expected`; returns the refusal's (code, message). Only ever called after a positive
        control on the same wiring has proven the credential live and the read reachable, so an
        over-permissive target never reaches the condition and the deadline miss IS the verdict."""
        def probe():
            try:
                fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                return err.get("Code"), err.get("Message")
            return _SUCCEEDED

        return _poll(
            probe,
            lambda r: r is not _SUCCEEDED and r[0] == expected,
            timeout_s=timeout_s,
            interval_s=3.0,
            description=f"{what} became refused with {expected}",
        )

    def _tags_kv(scenario):
        return [
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": scenario},
        ]

    account = sts.get_caller_identity()["Account"]

    def _trust_root():
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": ["sts:AssumeRole"],
                }
            ],
        }

    def _drop_role(role_name):
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
        _poll(
            lambda: _outcome(lambda: iam.get_role(RoleName=role_name)),
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
            lambda: _outcome(lambda: s3.head_bucket(Bucket=bucket)),
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
        # Tagged so a Resource Groups Tagging API search finds any remainder.
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _try_assume(client, role_arn, session_name):
        try:
            return client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, session_name):
        # Trust-policy propagation is real: the first AssumeRole against a new role fails for
        # seconds. This positive control runs BEFORE any negative assertion so a still-
        # propagating grant can never be read as a refusal.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name),
            lambda r: isinstance(r, dict),
            timeout_s=240.0,
            interval_s=3.0,
            description=f"role {role_arn} became assumable",
        )

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(
            lambda: _outcome(lambda: probe.get_caller_identity()),
            lambda c: c is _SUCCEEDED,
            timeout_s=180.0,
            interval_s=2.0,
            description="temporary credentials became active",
        )

    # ===== end helpers =====

    scenario = "sts-principal-arn-is-the-role-arn"
    bucket = _new_bucket(scenario)
    key = "principal-arn-form"
    payload = b"which-arn-form-does-the-request-context-carry"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    object_arn = f"arn:aws:s3:::{bucket}/{key}"

    role_name = ctx.unique_name("sim2real-behav-parn-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_root()),
        MaxSessionDuration=3600,
        Tags=_tags_kv(scenario),
    )["Role"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    role_arn = role["Arn"]

    policy_name = "principal-arn-form"

    def _put_policy(statement):
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
        )

    # --- BEAT 1: POSITIVE CONTROL. An unconditional Allow, so the session, the object, the
    # bucket and the re-signing seam are all proven good before a condition key is involved.
    _put_policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": object_arn})

    session_name = ctx.unique_name("sim2real-behav-sess-")
    creds = _wait_assumable(sts, role_arn, session_name)["Credentials"]
    _wait_creds_active(creds)
    sess_s3 = _client_with_credentials("s3", creds)
    sess_sts = _client_with_credentials("sts", creds)

    def _read():
        return sess_s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    def _poll_read(what):
        """The bytes of the first GetObject that succeeds. Grading the polled read itself keeps
        a replica that has not yet seen the policy from refusing a second, unpolled read."""
        def probe():
            try:
                return _read()
            except ClientError as exc:
                return exc.response.get("Error", {}).get("Code")

        return _poll(probe, lambda r: isinstance(r, bytes), timeout_s=_POLICY_DEADLINE_S,
                     interval_s=3.0, description=f"{what} became permitted")

    control_bytes = _poll_read("session GetObject under an unconditional Allow")
    assert control_bytes == payload, (
        f"positive control read wrong bytes from s3://{bucket}/{key}: expected {payload!r}, "
        f"got {control_bytes!r}"
    )

    # --- The two ARN forms, both read off the TARGET at runtime. No literal is pinned.
    session_arn = sess_sts.get_caller_identity()["Arn"]
    expected_prefix = f"arn:aws:sts::{account}:assumed-role/{role_name}/"
    assert session_arn.startswith(expected_prefix), (
        f"GetCallerIdentity for the assumed-role session returned an arn of the wrong shape: "
        f"expected it to start with {expected_prefix!r}, got {session_arn!r}"
    )
    fetched_role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    assert fetched_role_arn == role_arn, (
        f"GetRole disagrees with CreateRole about the role arn: expected {role_arn!r}, "
        f"got {fetched_role_arn!r}"
    )
    # VACUITY GUARD. If a target reported the same string for both, every remaining beat would
    # be comparing a value with itself. That is a FAIL here, never a silent pass.
    assert session_arn != role_arn, (
        f"the session arn and the role arn are the same string ({session_arn!r}), so this check "
        f"cannot distinguish the two forms -- GetCallerIdentity must return the "
        f"sts assumed-role form and GetRole the iam role form"
    )

    # --- BEAT 2: break EXACTLY ONE thing -- the condition value becomes the SESSION arn, which
    # is the string an emulator that echoes the caller identity would match on. Everything else
    # (action, resource, principal, credentials, object) is untouched.
    _put_policy(
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": object_arn,
            "Condition": {"StringEquals": {"aws:PrincipalArn": session_arn}},
        }
    )

    # --- BEAT 3: the SPECIFIC error code, polled to (never slept to).
    _denied_code, denied_message = _poll_denied(
        _read,
        "AccessDenied",
        what=f"session GetObject once the only Allow required aws:PrincipalArn == {session_arn}",
    )
    expected_denied_message = (
        f"User: {session_arn} is not authorized to perform: s3:GetObject on resource: "
        f'"{object_arn}" because no identity-based policy allows the s3:GetObject action'
    )
    assert denied_message == expected_denied_message, (
        f"expected the refusal message {expected_denied_message!r}, got {denied_message!r}"
    )

    # --- BEAT 4: the effect is absent through a DIFFERENT operation on the same object.
    # HeadObject is authorized by s3:GetObject too, so it must be refused as well; a target that
    # denied only the exact operation the check polled on is caught here.
    head_code = _error_code(lambda: sess_s3.head_object(Bucket=bucket, Key=key))
    # HeadObject carries no body, so the status is the whole refusal: there is no message.
    assert head_code == "403", (
        f"HeadObject on s3://{bucket}/{key} was not refused while the session's only Allow "
        f"required aws:PrincipalArn == the session arn: expected 403, "
        f"got {head_code!r}"
    )

    # --- BEAT 5: RESTORE, changing nothing but the ARN FORM in the condition value.
    _put_policy(
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": object_arn,
            "Condition": {"StringEquals": {"aws:PrincipalArn": role_arn}},
        }
    )

    # --- BEAT 6: the IDENTICAL call now succeeds, and the terminal assertion is an independent
    # read at the destination (S3), through an operation that is not the mutation
    # (put_role_policy), returning the exact bytes.
    restored = _poll_read(
        f"session GetObject once the condition value became the role arn {role_arn}"
    )
    assert restored == payload, (
        f"after the condition value was switched from the session arn to the role arn the "
        f"session read the wrong bytes from s3://{bucket}/{key}: expected {payload!r}, "
        f"got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
