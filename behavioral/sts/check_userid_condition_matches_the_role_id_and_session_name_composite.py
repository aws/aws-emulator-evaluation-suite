"""userid-condition-matches-the-role-id-and-session-name-composite."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "userid-condition-matches-the-role-id-and-session-name-composite"
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
    """`aws:userid` for an AssumeRole session is the `<RoleId>:<RoleSessionName>` composite (and
    GetCallerIdentity's UserId agrees): the exact composite and `<RoleId>:*` grant GetObject, while
    the RoleId alone, the session name alone or another session's composite grant nothing.
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # ===== helpers =====
    # The re-signing seam: ctx.client(creds=...) signs as the minted identity against the same target.
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

    def _try_assume(client, role_arn, session_name, **kw):
        try:
            return client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **kw)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, session_name):
        return _poll(
            lambda: _try_assume(client, role_arn, session_name),
            lambda r: isinstance(r, dict),
            timeout_s=_PROPAGATION_DEADLINE_S,
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

    # ===== end helpers =====

    scenario = "sts-userid-composite"
    bucket = _new_bucket(scenario)
    key = "userid-composite"
    payload = b"role-id-colon-session-name"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    object_arn = f"arn:aws:s3:::{bucket}/{key}"

    role_name = ctx.unique_name("sim2real-behav-userid-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_root()),
        MaxSessionDuration=3600,
        Tags=_tags_kv(scenario),
    )["Role"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    role_arn = role["Arn"]
    # The role's own identity policy allows the read UNCONDITIONALLY, so every outcome below is
    # decided by the session policy alone.
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

    # RoleId is read off the target, never pinned: it is minted at CreateRole time.
    role_id = iam.get_role(RoleName=role_name)["Role"]["RoleId"]
    assert role_id and role_id != role_name, (
        f"GetRole returned an implausible RoleId {role_id!r} for role {role_name!r}; the composite "
        f"this check is about cannot be built from it"
    )

    session_name = ctx.unique_name("sim2real-behav-sess-")
    other_session_name = ctx.unique_name("sim2real-behav-other-")
    assert session_name != other_session_name, "the two session names collided"
    composite = f"{role_id}:{session_name}"
    other_composite = f"{role_id}:{other_session_name}"

    # --- POSITIVE CONTROL: the session reads the object with NO session policy, proving the role,
    # the object, the credentials and IAM propagation before any condition key is involved.
    control_creds = _wait_assumable(sts, role_arn, session_name)["Credentials"]
    _wait_creds_active(control_creds)
    control_s3 = _client_with_credentials("s3", control_creds)
    _poll_allowed(
        lambda: control_s3.get_object(Bucket=bucket, Key=key),
        what="role session GetObject with no session policy",
    )
    control_bytes = control_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert control_bytes == payload, (
        f"positive control read wrong bytes from s3://{bucket}/{key}: expected {payload!r}, "
        f"got {control_bytes!r}"
    )

    # --- The identity API's own answer must equal the composite, so the two halves of the claim
    # (what STS reports, and what the authorization engine matches on) are pinned to each other.
    reported = _client_with_credentials("sts", control_creds).get_caller_identity()["UserId"]
    assert reported == composite, (
        f"GetCallerIdentity's UserId is not the documented <RoleId>:<RoleSessionName> composite: "
        f"expected {composite!r}, got {reported!r}"
    )

    # --- FIVE LEGS. Each mints a session named `session_name` from the same role with a session
    # policy that differs ONLY in the aws:userid condition it carries.
    def _read_code(condition):
        got = _try_assume(
            sts,
            role_arn,
            session_name,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": object_arn,
                            "Condition": condition,
                        }
                    ],
                }
            ),
        )
        assert isinstance(got, dict), (
            f"AssumeRole with a session policy carrying {condition} was itself refused with "
            f"{got!r}; a session policy is a scope-down, so AssumeRole must succeed and the "
            f"REQUEST must be judged later"
        )
        creds = got["Credentials"]
        _wait_creds_active(creds)
        client = _client_with_credentials("s3", creds)
        try:
            client.get_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message"), client
        return _SUCCEEDED, _SUCCEEDED, client

    exact_code, _, exact_client = _read_code({"StringEquals": {"aws:userid": composite}})
    assert exact_code == _SUCCEEDED, (
        f"the session was refused by a policy that allows exactly its own documented aws:userid "
        f"{composite!r}: expected the read to succeed, got error code {exact_code!r}"
    )

    role_id_glob = f"{role_id}:*"
    wildcard_code, _, _ = _read_code({"StringLike": {"aws:userid": role_id_glob}})
    assert wildcard_code == _SUCCEEDED, (
        f"the session was refused by StringLike aws:userid {role_id_glob!r}, so the value is "
        f"not the <RoleId>:<session> composite the docs describe: got error code "
        f"{wildcard_code!r}"
    )

    # The refusal S3 returns when the session policy's only Allow does not match.
    expected_denial = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{session_name} is not authorized "
        f'to perform: s3:GetObject on resource: "{object_arn}" because no session policy allows '
        f"the s3:GetObject action"
    )

    role_id_only_code, role_id_only_msg, _ = _read_code({"StringEquals": {"aws:userid": role_id}})
    assert role_id_only_code == "AccessDenied", (
        f"aws:userid matched the bare RoleId {role_id!r}, so the session name is missing from the "
        f"value the authorization engine sees: expected AccessDenied, got {role_id_only_code!r}"
    )
    assert role_id_only_msg == expected_denial, (
        f"the bare-RoleId refusal carries the wrong message: expected {expected_denial!r}, "
        f"got {role_id_only_msg!r}"
    )

    session_only_code, session_only_msg, _ = _read_code({"StringEquals": {"aws:userid": session_name}})
    assert session_only_code == "AccessDenied", (
        f"aws:userid matched the bare session name {session_name!r}, so the RoleId is missing from "
        f"the value the authorization engine sees: expected AccessDenied, got "
        f"{session_only_code!r}"
    )
    assert session_only_msg == expected_denial, (
        f"the bare-session-name refusal carries the wrong message: expected {expected_denial!r}, "
        f"got {session_only_msg!r}"
    )

    other_code, other_msg, _ = _read_code({"StringEquals": {"aws:userid": other_composite}})
    assert other_code == "AccessDenied", (
        f"aws:userid matched a composite for a DIFFERENT session name ({other_composite!r}) while "
        f"the session was named {session_name!r}, so the session name is not part of the matched "
        f"value: expected AccessDenied, got {other_code!r}"
    )
    assert other_msg == expected_denial, (
        f"the other-composite refusal carries the wrong message: expected {expected_denial!r}, "
        f"got {other_msg!r}"
    )

    # --- TERMINAL ASSERTION: an independent read at the destination (S3) by the session whose
    # aws:userid condition matched exactly, returning the exact bytes rather than a status.
    terminal = exact_client.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert terminal == payload, (
        f"the session allowed by StringEquals aws:userid == {composite!r} read the wrong bytes "
        f"from s3://{bucket}/{key}: expected {payload!r}, got {terminal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
