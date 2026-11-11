"""permissions-boundary-denies-an-action-the-roles-own-identity-policy-allows."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "permissions-boundary-denies-an-action-the-roles-own-identity-policy-allows"
GROUP = 'overly-permissive'
SERVICES = ['sts']

# What _outcome returns for a call that succeeded: an object no error code can equal.
_SUCCEEDED = object()


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose inline policy allows s3:* but whose permissions boundary allows only
    s3:ListBucket can list but not write, the refused write leaves no object, and detaching only
    the boundary makes the identical write succeed."""

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # Minted credentials are never written to os.environ and never appear in a message.
    def _client_with_credentials(service, creds, region=None):
        return ctx.client(service, region=region, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _outcome(fn):
        """The error CODE of a failing call, or _SUCCEEDED if it succeeded."""
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
        """Bounded poll to a condition. Raises on deadline miss."""
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
        """Poll until fn() SUCCEEDS. IAM/STS propagation is per-replica, so a replica can know a
        new key but not yet its policy; only polling on the expected success is race-free."""
        return _poll(lambda: _outcome(fn), lambda c: c is _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with EXACTLY `expected`; returns the refusal's (code, message).

        Called only after a positive control on the same session proved the credential live."""
        def probe():
            try:
                fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                return err.get("Code"), err.get("Message")
            return _SUCCEEDED

        return _poll(probe, lambda r: r is not _SUCCEEDED and r[0] == expected,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became refused with {expected}")

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(lambda: _outcome(lambda: probe.get_caller_identity()), lambda c: c is _SUCCEEDED,
              timeout_s=180.0, interval_s=2.0,
              description="temporary credentials became active")

    def _tags_kv(scenario):
        return [{"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real", "Value": scenario}]

    account = sts.get_caller_identity()["Account"]

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
        _poll(lambda: _outcome(lambda: iam.get_role(RoleName=role_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"role {role_name} disappeared")

    def _drop_role_if_present(role_name):
        """As _drop_role, but a no-op if the role is already gone."""
        if _outcome(lambda: iam.get_role(RoleName=role_name)) == "NoSuchEntity":
            return
        _drop_role(role_name)

    def _try_create_role(role_name, trust_policy, scenario):
        """create_role, returning the Role dict or the error CODE.

        IAM is eventually consistent about a new role as a trust principal and a freed name."""
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
        _poll(lambda: _outcome(lambda: c.head_bucket(Bucket=bucket)),
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
        c.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _try_assume(client, role_arn, **kw):
        """The AssumeRole response on success, or the error CODE string on failure."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-"), **kw)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, **kw):
        # The first AssumeRole against a new role fails for seconds while the trust policy
        # propagates; this positive control precedes any negative assertion.
        return _poll(lambda: _try_assume(client, role_arn, **kw), lambda r: isinstance(r, dict),
                     timeout_s=240.0, interval_s=3.0,
                     description=f"role {role_arn} became assumable")

    scenario = "sts-permissions-boundary"
    bucket = _new_bucket(scenario)
    payload = b"bound"
    control_key = "boundary-control-write"
    denied_key = "boundary-denied-write"

    # The boundary: a customer-managed policy allowing ONE s3 action on this bucket only.
    boundary_doc = _allow(["s3:ListBucket"], f"arn:aws:s3:::{bucket}")
    boundary = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-sts-pol-"),
        PolicyDocument=json.dumps(boundary_doc), Tags=_tags_kv(scenario))["Policy"]
    boundary_arn = boundary["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=boundary_arn))

    # The role: identity policy allows s3:* on the bucket and its objects -- strictly WIDER than
    # the boundary, which is the whole point.
    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_trust_root()),
        MaxSessionDuration=3600, PermissionsBoundary=boundary_arn,
        Tags=_tags_kv(scenario))["Role"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    role_arn = role["Arn"]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-inline",
        PolicyDocument=json.dumps(
            _allow(["s3:*"], [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"])))

    desc = iam.get_role(RoleName=role_name)["Role"]
    assert boundary_arn == desc.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"), (
        "the boundary did not attach: GetRole reports "
        f"{desc.get('PermissionsBoundary')!r}, expected PermissionsBoundaryArn {boundary_arn!r}")

    session = _wait_assumable(sts, role_arn)
    _wait_creds_active(session["Credentials"])
    scoped = _client_with_credentials("s3", session["Credentials"])

    # --- POSITIVE half: the action in the INTERSECTION of identity-allow and boundary-allow.
    # This is also the propagation barrier: until it works, nothing below is a policy decision.
    _poll_allowed(lambda: scoped.list_objects_v2(Bucket=bucket, MaxKeys=1),
                  what="boundary-permitted s3:ListBucket under the scoped session")
    listed = scoped.list_objects_v2(Bucket=bucket, MaxKeys=1)
    assert listed["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        "the boundary-permitted operation failed, so the intersection cannot be isolated as the "
        f"cause of anything below: {listed.get('ResponseMetadata')!r}")

    # --- Break exactly ONE thing: an action the identity policy allows and the boundary does not.
    put_code, put_message = _poll_denied(
        lambda: scoped.put_object(Bucket=bucket, Key=denied_key, Body=payload), "AccessDenied",
        what="s3:PutObject outside the permissions boundary")
    assert put_code == "AccessDenied", (
        "a write outside the permissions boundary must be denied even though the role's own "
        f"identity policy allows s3:* on this bucket; got {put_code!r}. Anything other than "
        "AccessDenied -- including a success -- means the boundary was not evaluated")
    expected_put_message = (
        f"User: {session['AssumedRoleUser']['Arn']} is not authorized to perform: s3:PutObject "
        f'on resource: "arn:aws:s3:::{bucket}/{denied_key}" because no permissions boundary '
        "allows the s3:PutObject action")
    assert put_message == expected_put_message, (
        f"expected the refusal message {expected_put_message!r}, got {put_message!r}")

    # --- EFFECT ABSENT: the refused write left nothing behind, checked with the bucket owner's
    # identity so the observation does not depend on the scoped session's permissions.
    head_code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=denied_key))
    assert head_code == "404", (
        f"the denied PutObject left an object behind at {denied_key!r}: HeadObject by the bucket "
        f"owner returned {head_code!r} instead of 404")

    # --- POSITIVE CONTROL: detach the boundary, change nothing else, and the IDENTICAL write must
    # succeed and round-trip its bytes. A fresh session is used because a boundary change does
    # not deterministically apply to an already-issued session.
    iam.delete_role_permissions_boundary(RoleName=role_name)
    control_session = _wait_assumable(sts, role_arn)
    _wait_creds_active(control_session["Credentials"])
    unbounded = _client_with_credentials("s3", control_session["Credentials"])
    _poll_allowed(lambda: unbounded.put_object(Bucket=bucket, Key=control_key, Body=payload),
                  what="s3:PutObject with the permissions boundary detached")
    control_body = unbounded.get_object(Bucket=bucket, Key=control_key)["Body"].read()
    assert control_body == payload, (
        "positive control: with the boundary detached the identical write must succeed and round "
        f"-trip; got {control_body!r} instead of {payload!r}")

    # --- The boundary was the ONLY thing that changed: GetRole must now report no boundary, and the
    # role's own inline policy must be byte-identical to what it was when the write was refused.
    after = iam.get_role(RoleName=role_name)["Role"]
    assert after.get("PermissionsBoundary") is None, (
        "the control leg must have detached the boundary and nothing else; GetRole still reports "
        f"{after.get('PermissionsBoundary')!r}")
    still_inline = iam.get_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-inline")["PolicyDocument"]
    assert still_inline == _allow(
        ["s3:*"], [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]), (
        "the role's own identity policy must be unchanged across both legs, or the denial and the "
        f"success differ by more than the boundary; IAM reports {still_inline!r}")

    # --- and the earlier refusal is still the only reason that key is absent: the control wrote to
    # its own key, so the denied key must STILL not exist.
    head_again = _error_code(lambda: s3.head_object(Bucket=bucket, Key=denied_key))
    assert head_again == "404", (
        f"the key the boundary-denied PutObject named must still be absent after the control wrote "
        f"to a different key; HeadObject returned {head_again!r} instead of 404")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
