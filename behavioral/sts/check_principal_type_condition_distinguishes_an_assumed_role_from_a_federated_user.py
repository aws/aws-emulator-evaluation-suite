"""principal-type-condition-distinguishes-an-assumed-role-from-a-federated-user."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "principal-type-condition-distinguishes-an-assumed-role-from-a-federated-user"
GROUP = "overly-permissive"
SERVICES = ["sts"]

_PROPAGATION_DEADLINE_S = 240.0
# Documented aws:PrincipalType values; for each caller exactly one must allow.
_TYPES = ("AssumedRole", "FederatedUser", "User")
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
    """`aws:PrincipalType` is "AssumedRole" for an AssumeRole session and "FederatedUser" for a
    GetFederationToken session: of three session policies gated on each value, exactly one lets
    each caller read the S3 object."""
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
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(
            lambda: _error_code(lambda: probe.get_caller_identity()),
            lambda c: c == _SUCCEEDED,
            timeout_s=180.0,
            interval_s=2.0,
            description="temporary credentials became active",
        )

    scenario = "sts-principal-type-permutation"
    bucket = _new_bucket(scenario)
    key = "principal-type"
    payload = b"which-principal-type-does-the-request-context-carry"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    object_arn = f"arn:aws:s3:::{bucket}/{key}"

    def _session_policy(principal_type):
        """A session policy whose ONLY Allow is gated on aws:PrincipalType == principal_type.
        The three variants differ in exactly that one string."""
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": object_arn,
                        "Condition": {"StringEquals": {"aws:PrincipalType": principal_type}},
                    }
                ],
            }
        )

    # Caller 1: an AssumeRole session whose role policy allows the read unconditionally, so the
    # session policy alone decides each outcome.
    role_name = ctx.unique_name("sim2real-behav-ptype-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_root()),
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

    # Caller 2: a GetFederationToken session, which only an IAM user's long-term key may
    # obtain. Its permissions intersect the user's policy, so that policy allows the read
    # unconditionally.
    user_name = ctx.unique_name("sim2real-behav-ptype-user-")
    iam.create_user(UserName=user_name, Tags=_tags_kv(scenario))
    ctx.on_cleanup(lambda: _drop_user(user_name))
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="federate-and-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": object_arn},
                    {"Effect": "Allow", "Action": "sts:GetFederationToken", "Resource": "*"},
                ],
            }
        ),
    )
    user_key = iam.create_access_key(UserName=user_name)["AccessKey"]

    # Positive control A: the role session reads with no session policy, so IAM propagation is
    # complete before any condition key is in play.
    plain_creds = _wait_assumable(sts, role_arn, ctx.unique_name("sim2real-behav-sess-"))[
        "Credentials"
    ]
    _wait_creds_active(plain_creds)
    plain_s3 = _client_with_credentials("s3", plain_creds)
    _poll_allowed(
        lambda: plain_s3.get_object(Bucket=bucket, Key=key),
        what="role session GetObject with no session policy",
    )
    control_bytes = plain_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert control_bytes == payload, (
        f"positive control A read wrong bytes from s3://{bucket}/{key}: expected {payload!r}, "
        f"got {control_bytes!r}"
    )

    # Positive control B: the IAM user's long-term key reads the object.
    user_s3 = _client_with_credentials("s3", user_key)
    _poll_allowed(
        lambda: user_s3.get_object(Bucket=bucket, Key=key),
        what=f"IAM user {user_name} GetObject on its own long-term key",
    )

    # Six legs, one object, one action, no policy edit between them: a session policy is baked
    # into the credential at issuance, so no leg depends on propagation.
    def _role_session_read_code(principal_type):
        got = _try_assume(
            sts,
            role_arn,
            ctx.unique_name("sim2real-behav-sess-"),
            Policy=_session_policy(principal_type),
        )
        assert isinstance(got, dict), (
            f"AssumeRole with a session policy gated on aws:PrincipalType == {principal_type!r} "
            f"was itself refused with {got!r}; the session policy is a scope-down, not a "
            f"trust decision, so AssumeRole must succeed and the REQUEST must be judged later"
        )
        creds = got["Credentials"]
        _wait_creds_active(creds)
        client = _client_with_credentials("s3", creds)
        return _error_code(lambda: client.get_object(Bucket=bucket, Key=key)), client

    def _fed_session_read_code(principal_type):
        fed = _client_with_credentials("sts", user_key).get_federation_token(
            Name=ctx.unique_name("fed-")[:32],
            Policy=_session_policy(principal_type),
            DurationSeconds=900,
        )
        creds = fed["Credentials"]
        _wait_creds_active(creds)
        client = _client_with_credentials("s3", creds)
        return _error_code(lambda: client.get_object(Bucket=bucket, Key=key)), client

    role_outcomes = {}
    role_clients = {}
    for principal_type in _TYPES:
        role_outcomes[principal_type], role_clients[principal_type] = _role_session_read_code(
            principal_type
        )

    fed_outcomes = {}
    for principal_type in _TYPES:
        fed_outcomes[principal_type], _ = _fed_session_read_code(principal_type)

    # One-hot per caller: exactly one value may allow, and every other must be AccessDenied.
    expected_role = {"AssumedRole": _SUCCEEDED, "FederatedUser": "AccessDenied", "User": "AccessDenied"}
    expected_fed = {"FederatedUser": _SUCCEEDED, "AssumedRole": "AccessDenied", "User": "AccessDenied"}
    assert role_outcomes == expected_role, (
        f"aws:PrincipalType is wrong for an AssumeRole session: expected {expected_role} "
        f"({_SUCCEEDED!r} = the read succeeded), got {role_outcomes}"
    )
    assert fed_outcomes == expected_fed, (
        f"aws:PrincipalType is wrong for a GetFederationToken session: expected {expected_fed} "
        f"({_SUCCEEDED!r} = the read succeeded), got {fed_outcomes}"
    )

    # The matching session reads back the exact bytes, not merely a success status.
    terminal = role_clients["AssumedRole"].get_object(Bucket=bucket, Key=key)["Body"].read()
    assert terminal == payload, (
        f"the AssumedRole-gated session read the wrong bytes from s3://{bucket}/{key}: "
        f"expected {payload!r}, got {terminal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
