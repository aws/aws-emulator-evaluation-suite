"""deleting-the-role-invalidates-credentials-already-issued-and-recreating-it-by-name-does-not-restore-them."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "deleting-the-role-invalidates-credentials-already-issued-and-recreating-it-by-name-does-not-restore-them"
)
GROUP = 'credential-issuance'
SERVICES = ['sts']

_SUCCEEDED = "<call succeeded>"
_UNKNOWN_KEY_MESSAGE = "The AWS Access Key Id you provided does not exist in our records."


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting a role makes sessions already issued from it fail with InvalidAccessKeyId, and
    recreating the role by name with identical policies does not restore them (new RoleId), while
    a session assumed from the recreated role reads the object normally."""

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # Minted credentials never go to os.environ or into assertion messages.

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
        """The error CODE of a failing call, or the _SUCCEEDED sentinel if it succeeded. The
        sentinel is not code-shaped, so an unexpected success never equals an expected code."""
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _SUCCEEDED

    def _refusal(fn):
        """The (code, message) of a failing call; raises AssertionError when it succeeds."""
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("expected a refusal, but the call succeeded")

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
        """Bounded poll to a condition. Raises on deadline miss -- never a bare sleep."""
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})")
            time.sleep(interval_s)

    def _poll_allowed(fn, *, timeout_s=240.0, what="call"):
        """Poll until fn() SUCCEEDS: IAM/STS propagation is per-replica, so a replica holding a new
        key can still lack its policy and a single-shot success assertion is racy."""
        return _poll(lambda: _error_code(fn), lambda c: c == _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with EXACTLY `expected`; raises on deadline."""
        return _poll(lambda: _error_code(fn), lambda c: c == expected,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became refused with {expected}")

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(lambda: _error_code(lambda: probe.get_caller_identity()), lambda c: c == _SUCCEEDED,
              timeout_s=180.0, interval_s=2.0,
              description="temporary credentials became active")

    def _tags_kv(scenario):
        return [{"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real", "Value": scenario}]

    account = ctx.account

    def _trust_root():
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
             "Action": ["sts:AssumeRole"]}]}

    def _allow(actions, resource="*"):
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": resource}]}

    def _drop_role(role_name):
        # Attached managed policies, inline policies AND a permissions boundary all block
        # delete_role, so all three come off first; then poll to actual disappearance.
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        if iam.get_role(RoleName=role_name)["Role"].get("PermissionsBoundary"):
            iam.delete_role_permissions_boundary(RoleName=role_name)
        iam.delete_role(RoleName=role_name)
        _poll(lambda: _error_code(lambda: iam.get_role(RoleName=role_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"role {role_name} disappeared")

    def _drop_role_if_present(role_name):
        """As _drop_role, but a no-op if the role is already gone."""
        if _error_code(lambda: iam.get_role(RoleName=role_name)) == "NoSuchEntity":
            return
        _drop_role(role_name)

    def _try_create_role(role_name, trust_policy, scenario):
        """create_role, returning the Role dict or the error CODE: IAM is eventually consistent
        about a just-deleted role name becoming free again."""
        try:
            return iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
                MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _drop_bucket(bucket, client=None):
        c = client or s3
        for page in c.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                c.delete_object(Bucket=bucket, Key=obj["Key"])
        c.delete_bucket(Bucket=bucket)
        _poll(lambda: _error_code(lambda: c.head_bucket(Bucket=bucket)),
              lambda code: code in {"404", "NoSuchBucket"}, timeout_s=90.0, interval_s=2.0,
              description=f"bucket {bucket} disappeared")

    def _new_bucket(scenario, client=None, region=None):
        c = client or s3
        bucket = ctx.unique_name("sim2real-behav-sts-")
        params = {"Bucket": bucket}
        target_region = region or ctx.region
        if target_region and target_region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": target_region}
        c.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(bucket, c))
        # Tagged so tag-based cleanup can find it.
        c.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _try_assume(client, role_arn, **kw):
        """The AssumeRole response on success, or the error CODE string on failure -- so
        `result == "AccessDenied"` proves the code AND that no credentials were issued."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-"), **kw)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, **kw):
        # Trust-policy propagation is real: the first AssumeRole against a new role fails for
        # seconds. Establishing this positive control BEFORE any negative assertion is what keeps
        # a still-propagating grant from being read as a refusal.
        return _poll(lambda: _try_assume(client, role_arn, **kw), lambda r: isinstance(r, dict),
                     timeout_s=240.0, interval_s=3.0,
                     description=f"role {role_arn} became assumable")

    scenario = "sts-deleted-role-invalidates-sessions"
    bucket = _new_bucket(scenario)
    payload = b"role-identity"
    key = "deleted-role-object"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    objects_arn = f"arn:aws:s3:::{bucket}/*"

    trust = _trust_root()
    inline = _allow(["s3:GetObject"], objects_arn)

    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    created = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]
    # Registered immediately, and tolerant of the role already being gone -- this check deletes it
    # itself halfway through and then recreates it under the same name.
    ctx.on_cleanup(lambda: _drop_role_if_present(role_name))
    old_role_id = created["RoleId"]
    role_arn = created["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(inline))

    # --- Session OLD, and the propagation barrier: it must demonstrably read the object first.
    old = _wait_assumable(sts, role_arn)
    _wait_creds_active(old["Credentials"])
    old_s3 = _client_with_credentials("s3", old["Credentials"])
    _poll_allowed(lambda: old_s3.get_object(Bucket=bucket, Key=key),
                  what="session OLD reading the object the role grants")
    old_read_before = old_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert old_read_before == payload, (
        "the session could not read the object before the role was deleted, so there is nothing to "
        f"invalidate; got {old_read_before!r}")

    # --- Break exactly one thing: delete the role. Nothing about the object, the bucket or the
    # credentials changes.
    _drop_role(role_name)
    code_after_delete = _poll(
        lambda: _error_code(lambda: old_s3.get_object(Bucket=bucket, Key=key)),
        lambda c: c != _SUCCEEDED, timeout_s=240.0, interval_s=3.0,
        description="session OLD stopped working after its role was deleted")
    assert code_after_delete == "InvalidAccessKeyId", (
        "a session issued from a role that has since been deleted must be rejected with "
        f"InvalidAccessKeyId -- at credential resolution, before any policy is consulted; got "
        f"{code_after_delete!r}")
    refusal_after_delete = _refusal(lambda: old_s3.get_object(Bucket=bucket, Key=key))
    assert refusal_after_delete == ("InvalidAccessKeyId", _UNKNOWN_KEY_MESSAGE), refusal_after_delete

    # --- Recreate the role by NAME with byte-identical policies. The only thing that cannot be
    # recreated is the RoleId, and that is the whole mechanism.
    recreated = _poll(
        lambda: _try_create_role(role_name, trust, scenario), lambda r: isinstance(r, dict),
        timeout_s=180.0, interval_s=3.0,
        description=f"role {role_name} could be recreated under the same name")
    new_role_id = recreated["RoleId"]
    new_role_arn = recreated["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(inline))
    assert old_role_id != new_role_id, (
        f"the recreated role reused the RoleId {new_role_id!r}, which would invalidate the premise of "
        "this check -- the claim is that a role's identity is its id and not its name")
    assert new_role_arn == role_arn, (
        "the recreated role must carry the IDENTICAL ARN, so the only difference between the two "
        f"roles is the RoleId; got {new_role_arn!r} != {role_arn!r}")
    assert iam.get_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-inline")["PolicyDocument"] == inline, (
        "the recreated role's inline policy must be byte-identical to the deleted role's, or the old "
        "session's continued failure could be explained by a different grant")

    # --- The load-bearing assertion, and the one that does not depend on which code AWS chose: the
    # OLD session's outcome is UNCHANGED by the recreation.
    code_after_recreate = _poll(
        lambda: _error_code(lambda: old_s3.get_object(Bucket=bucket, Key=key)),
        lambda c: c == code_after_delete, timeout_s=180.0, interval_s=3.0,
        description="session OLD kept failing with the same code after the role was recreated")
    assert code_after_recreate == code_after_delete, (
        "recreating the role by name must NOT change the outcome for the OLD session: "
        f"{code_after_delete!r} became {code_after_recreate!r}. A success here would mean sessions "
        "are bound to a role NAME, so deleting a leaked role would not actually revoke anything")
    refusal_after_recreate = _refusal(lambda: old_s3.get_object(Bucket=bucket, Key=key))
    assert refusal_after_recreate == ("InvalidAccessKeyId", _UNKNOWN_KEY_MESSAGE), refusal_after_recreate

    # --- POSITIVE CONTROL: a session from the recreated role reads the same object. This separates
    # "the old credentials are dead" from "the bucket, the object or the policy broke".
    new = _wait_assumable(sts, role_arn)
    _wait_creds_active(new["Credentials"])
    new_s3 = _client_with_credentials("s3", new["Credentials"])
    _poll_allowed(lambda: new_s3.get_object(Bucket=bucket, Key=key),
                  what="a session from the RECREATED role reading the same object")
    new_read = new_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert new_read == payload, (
        "positive control: a session from the recreated role must read the object normally; got "
        f"{new_read!r} instead of {payload!r}")

    # --- and the new session really is a different principal: its UserId carries the NEW RoleId.
    new_ident = _client_with_credentials("sts", new["Credentials"]).get_caller_identity()
    assert new_ident["UserId"].split(":", 1)[0] == new_role_id, (
        "the new session's UserId must carry the RECREATED role's id, which is the identifier the "
        f"old credentials no longer resolve to; got {new_ident['UserId']!r} for role id "
        f"{new_role_id!r}")

    # --- EFFECT SCOPING: the object is intact and readable by its owner throughout.
    runner_read = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert runner_read == payload, (
        f"the object itself became unreadable to its owner, so nothing was proven; got {runner_read!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
