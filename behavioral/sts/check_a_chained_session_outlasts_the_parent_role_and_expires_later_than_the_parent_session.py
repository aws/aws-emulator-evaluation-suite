"""a-chained-session-outlasts-the-parent-role-and-expires-later-than-the-parent-session."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-chained-session-outlasts-the-parent-role-and-expires-later-than-the-parent-session"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]

_PARENT_DURATION_S = 900  # AssumeRole's documented hard-floor minimum
_CHILD_DURATION_S = 3600  # the documented role-chaining maximum
_REVOCATION_DEADLINE_S = 180.0
_FREEZE_READS = 3
_SUCCEEDED = "<call succeeded>"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A chained session is independent of its parent: its Expiration may land later than the
    parent's, and deleting the parent role leaves it working while the parent's S3 reads fail.

    Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
    """
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
        """The error code ``fn`` raises, or ``_SUCCEEDED`` (equal to no AWS code) when it succeeds."""
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

    def _trust(principal_arn):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal_arn},
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
            lambda: _error_code(lambda: iam.get_role(RoleName=role_name)),
            lambda c: c == "NoSuchEntity",
            timeout_s=90.0,
            interval_s=2.0,
            description=f"role {role_name} disappeared",
        )

    def _drop_role_if_present(role_name):
        if _error_code(lambda: iam.get_role(RoleName=role_name)) == "NoSuchEntity":
            return
        _drop_role(role_name)

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

    def _try_assume(client, role_arn, session_name, **kw):
        try:
            return client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **kw)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, session_name, **kw):
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
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

    scenario = "sts-chained-session-independence"
    bucket = _new_bucket(scenario)
    key = "chained-session"
    payload = b"a-chained-session-is-its-own-credential"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    object_arn = f"arn:aws:s3:::{bucket}/{key}"

    child_role_name = ctx.unique_name("sim2real-behav-child-")
    parent_role_name = ctx.unique_name("sim2real-behav-parent-")
    parent_role_arn = f"arn:aws:iam::{account}:role/{parent_role_name}"

    # The parent can read the object too, so its liveness is probed with the same operation.
    parent_created = iam.create_role(
        RoleName=parent_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust(f"arn:aws:iam::{account}:root")),
        MaxSessionDuration=3600,
        Tags=_tags_kv(scenario),
    )["Role"]
    ctx.on_cleanup(lambda: _drop_role_if_present(parent_role_name))
    assert parent_created["Arn"] == parent_role_arn, (
        f"the parent role's arn is not the one role B's trust policy was written for: expected "
        f"{parent_role_arn!r}, got {parent_created['Arn']!r}"
    )

    # IAM is eventually consistent about a new role ARN as a trust-policy principal: it answers
    # MalformedPolicyDocument ("Invalid principal in policy") for a role that exists.
    def _try_create_child():
        try:
            return iam.create_role(
                RoleName=child_role_name,
                AssumeRolePolicyDocument=json.dumps(_trust(parent_role_arn)),
                MaxSessionDuration=3600,
                Tags=_tags_kv(scenario),
            )["Role"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "MalformedPolicyDocument":
                raise
            return code

    child_role_arn = _poll(
        _try_create_child,
        lambda r: isinstance(r, dict),
        timeout_s=120.0,
        interval_s=3.0,
        description=(
            f"role {parent_role_name} became usable as a trust-policy principal for "
            f"{child_role_name}"
        ),
    )["Arn"]
    ctx.on_cleanup(lambda: _drop_role_if_present(child_role_name))

    iam.put_role_policy(
        RoleName=parent_role_name,
        PolicyName="chain-and-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": child_role_arn},
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": object_arn},
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName=child_role_name,
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

    parent = _wait_assumable(
        sts,
        parent_role_arn,
        ctx.unique_name("sim2real-behav-parent-sess-"),
        DurationSeconds=_PARENT_DURATION_S,
    )
    parent_creds = parent["Credentials"]
    parent_expiration = parent_creds["Expiration"]
    _wait_creds_active(parent_creds)
    parent_s3 = _client_with_credentials("s3", parent_creds)
    parent_sts = _client_with_credentials("sts", parent_creds)
    _poll_allowed(
        lambda: parent_s3.get_object(Bucket=bucket, Key=key),
        what="the parent session reading the object",
    )

    # Ask for the full 3600s chaining cap from a parent with at most _PARENT_DURATION_S left.
    child = _wait_assumable(
        parent_sts,
        child_role_arn,
        ctx.unique_name("sim2real-behav-child-sess-"),
        DurationSeconds=_CHILD_DURATION_S,
    )
    child_creds = child["Credentials"]
    child_expiration = child_creds["Expiration"]
    _wait_creds_active(child_creds)

    assert child["AssumedRoleUser"]["Arn"].startswith(
        f"arn:aws:sts::{account}:assumed-role/{child_role_name}/"
    ), (
        f"the chained session does not present as a session of the child role: expected an "
        f"assumed-role arn for {child_role_name}, got {child['AssumedRoleUser']['Arn']!r}"
    )

    # The separation bound is derived from the two requested durations, with 60s of slack.
    parent_remaining_s = parent_expiration.timestamp() - time.time()
    separation_s = child_expiration.timestamp() - parent_expiration.timestamp()
    minimum_separation_s = _CHILD_DURATION_S - _PARENT_DURATION_S - 60
    assert separation_s >= minimum_separation_s, (
        f"the chained session's Expiration is not independent of its parent's: child expires "
        f"{separation_s:.0f}s after the parent, expected at least {minimum_separation_s}s "
        f"(child asked for {_CHILD_DURATION_S}s, parent asked for {_PARENT_DURATION_S}s and had "
        f"{parent_remaining_s:.0f}s left when the child was minted)"
    )
    assert parent_remaining_s <= _PARENT_DURATION_S, (
        f"the parent session has MORE than the {_PARENT_DURATION_S}s it asked for remaining "
        f"({parent_remaining_s:.0f}s), so the separation above proves nothing about the child"
    )

    child_s3 = _client_with_credentials("s3", child_creds)
    _poll_allowed(
        lambda: child_s3.get_object(Bucket=bucket, Key=key),
        what="the chained session reading the object",
    )
    control_bytes = child_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert control_bytes == payload, (
        f"positive control: the chained session read the wrong bytes from s3://{bucket}/{key}: "
        f"expected {payload!r}, got {control_bytes!r}"
    )

    _drop_role(parent_role_name)

    # Barrier: the parent's own session fails, so the child's survival is not just propagation lag.
    _poll(
        lambda: _error_code(lambda: parent_s3.get_object(Bucket=bucket, Key=key)),
        lambda c: c == "InvalidAccessKeyId",
        timeout_s=_REVOCATION_DEADLINE_S,
        interval_s=3.0,
        description=(
            f"the parent session's GetObject began failing InvalidAccessKeyId after role "
            f"{parent_role_name} was deleted"
        ),
    )
    # STS's own AssumeRole does not re-check that the caller's source role still exists, so the
    # dead parent may keep minting sessions; a refusal is also accepted, but each minted session
    # must work.
    for attempt in range(_FREEZE_READS):
        try:
            grandchild = parent_sts.assume_role(
                RoleArn=child_role_arn,
                RoleSessionName=ctx.unique_name("sim2real-behav-grandchild-sess-"),
            )
        except ClientError:
            break
        assert grandchild["AssumedRoleUser"]["Arn"].startswith(
            f"arn:aws:sts::{account}:assumed-role/{child_role_name}/"
        ), (
            f"attempt {attempt + 1} of {_FREEZE_READS}: the dead parent session's AssumeRole did "
            f"not mint a session of the child role: got {grandchild['AssumedRoleUser']['Arn']!r}"
        )
        grandchild_creds = grandchild["Credentials"]
        _wait_creds_active(grandchild_creds)
        grandchild_s3 = _client_with_credentials("s3", grandchild_creds)
        grandchild_bytes = grandchild_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert grandchild_bytes == payload, (
            f"attempt {attempt + 1} of {_FREEZE_READS}: a session chained from the DEAD parent "
            f"session (its own role already deleted) could not read s3://{bucket}/{key} through "
            f"the child role: expected {payload!r}, got {grandchild_bytes!r} -- AWS's own contract "
            f"is that STS's AssumeRole does not re-check the caller's source role at call time"
        )

    # Repeated reads catch a target that invalidates lazily on a later call.
    for attempt in range(_FREEZE_READS):
        after_bytes = child_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert after_bytes == payload, (
            f"read {attempt + 1} of {_FREEZE_READS} by the chained session returned the wrong "
            f"bytes from s3://{bucket}/{key} after the PARENT role was deleted: expected "
            f"{payload!r}, got {after_bytes!r} -- a chained session belongs to the child role, not "
            f"to the session that minted it"
        )

    # Re-read the child's identity so survival cannot be a substituted principal.
    child_sts = _client_with_credentials("sts", child_creds)
    child_identity = child_sts.get_caller_identity()["Arn"]
    assert child_identity == child["AssumedRoleUser"]["Arn"], (
        f"the chained session's identity changed after the parent role was deleted: expected "
        f"{child['AssumedRoleUser']['Arn']!r}, got {child_identity!r}"
    )
    terminal = child_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert terminal == payload, (
        f"the chained session could not read s3://{bucket}/{key} once its parent role was gone: "
        f"expected {payload!r}, got {terminal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
