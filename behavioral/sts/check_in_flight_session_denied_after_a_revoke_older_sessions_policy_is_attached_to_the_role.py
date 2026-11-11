"""in-flight-session-denied-after-a-revoke-older-sessions-policy-is-attached-to-the-role."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "in-flight-session-denied-after-a-revoke-older-sessions-policy-is-attached-to-the-role"
GROUP = 'overly-permissive'
SERVICES = ['sts']

# What _outcome returns for a call that succeeded: an object no error code can equal.
_SUCCEEDED = object()

_REVOKE_POLICY_NAME = "sim2real-behav-revoke-older-sessions"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Deny-all role policy with aws:TokenIssueTime DateLessThan a cut-off denies an already
    issued session; a session issued after the cut-off still reads, and removing the Deny restores the old.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
    """

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # Minted credentials never go to os.environ or into an assertion message.
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
        """Poll until fn() SUCCEEDS. IAM/STS propagation is per-replica, so a replica can know a
        new key but not yet its policy; only polling on the expected success is a safe barrier."""
        return _poll(lambda: _outcome(fn), lambda c: c is _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with EXACTLY `expected`; return the refusal's (code, message).
        Called only after a positive control proved the credential live."""
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
        """create_role, returning the Role dict or the error CODE. A just-created role ARN can be
        refused as a trust-policy principal ("Invalid principal in policy") until IAM converges."""
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
        # us-east-1 is a genuine S3 CreateBucket quirk: it rejects an explicit LocationConstraint.
        if target_region and target_region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": target_region}
        c.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(bucket, c))
        # Tagged so tag-based cleanup (Resource Groups Tagging API) can find it.
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

    def _issued_at(session, duration_s):
        """The session's issue instant, derived from the server-supplied Expiration: the
        claim is about a server-side time comparison."""
        return session["Credentials"]["Expiration"] - dt.timedelta(seconds=duration_s)

    scenario = "sts-revoke-older-sessions"
    duration = 900
    bucket = _new_bucket(scenario)
    payload = b"revocable"
    key = "revoke-older-sessions-object"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)

    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_trust_root()),
        MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-inline",
        PolicyDocument=json.dumps(_allow(["s3:GetObject"], f"arn:aws:s3:::{bucket}/*")))

    # --- Session OLD, and the propagation barrier: it must demonstrably read the object BEFORE
    # anything is revoked. Without this leg a later AccessDenied could be an unpropagated grant.
    old = _wait_assumable(sts, role_arn, DurationSeconds=duration)
    old_issued_at = _issued_at(old, duration)
    _wait_creds_active(old["Credentials"])
    old_s3 = _client_with_credentials("s3", old["Credentials"])
    _poll_allowed(lambda: old_s3.get_object(Bucket=bucket, Key=key),
                  what="session OLD reading the object it is granted")
    old_read_before = old_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert old_read_before == payload, (
        "the pre-revocation session could not read the object, so there is nothing to revoke; got "
        f"{old_read_before!r} instead of {payload!r}")

    # --- Break exactly one thing: the cut-off, strictly after OLD's issue instant.
    cutoff = old_issued_at + dt.timedelta(seconds=10)
    revoke_doc = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Action": ["*"], "Resource": ["*"],
         "Condition": {"DateLessThan": {
             "aws:TokenIssueTime": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")}}}]}
    iam.put_role_policy(RoleName=role_name, PolicyName=_REVOKE_POLICY_NAME,
                        PolicyDocument=json.dumps(revoke_doc))
    # Registered before the assertions so a failure cannot leave an all-Deny policy attached.
    # The sole-cause leg removes the policy itself, so a not-found here is the norm. The Deny is an
    # identity policy on this role only, so teardown with the caller's credentials is unaffected.
    def _drop_revoke_policy():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=_REVOKE_POLICY_NAME)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_drop_revoke_policy)

    old_code_after, old_message_after = _poll_denied(
        lambda: old_s3.get_object(Bucket=bucket, Key=key), "AccessDenied",
        what="session OLD after the revoke-older-sessions policy was attached")
    assert old_code_after == "AccessDenied", (
        "a session whose aws:TokenIssueTime precedes the cut-off must be denied by the "
        f"DateLessThan Deny; got {old_code_after!r}")
    expected_old_message = (
        f"User: {old['AssumedRoleUser']['Arn']} is not authorized to perform: s3:GetObject on "
        f'resource: "arn:aws:s3:::{bucket}/{key}" with an explicit deny in an identity-based '
        "policy")
    assert old_message_after == expected_old_message, (
        f"expected the refusal message {expected_old_message!r}, got {old_message_after!r}")

    # --- POSITIVE CONTROL: a session issued AFTER the cut-off, with the Deny still attached, is
    # unaffected; this separates "the revocation worked" from "the role is broken".
    new = _wait_assumable(sts, role_arn, DurationSeconds=duration)
    new_issued_at = _issued_at(new, duration)
    new_deadline = time.monotonic() + 60.0
    while new_issued_at <= cutoff:
        # Re-assume until the server-supplied issue instant is past the cut-off so the assertion
        # below cannot flake on timing; bounded so a non-advancing issue instant raises.
        if time.monotonic() >= new_deadline:
            raise AssertionError(
                "session NEW's server-supplied issue instant never advanced past the cutoff within "
                f"60s (last issued_at={new_issued_at.isoformat()}, cutoff={cutoff.isoformat()})")
        time.sleep(3)
        new = _wait_assumable(sts, role_arn, DurationSeconds=duration)
        new_issued_at = _issued_at(new, duration)
    _wait_creds_active(new["Credentials"])
    new_s3 = _client_with_credentials("s3", new["Credentials"])
    _poll_allowed(lambda: new_s3.get_object(Bucket=bucket, Key=key),
                  what="session NEW, issued after the cut-off, reading the same object")
    new_read = new_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert new_read == payload, (
        "positive control: a session issued AFTER the cut-off must be unaffected by the Deny and "
        f"read the same object; got {new_read!r} instead of {payload!r}")

    assert old_issued_at < cutoff <= new_issued_at, (
        "the cut-off must fall strictly between the two sessions' server-supplied issue instants, "
        f"or neither leg proves anything: old={old_issued_at.isoformat()} "
        f"cutoff={cutoff.isoformat()} new={new_issued_at.isoformat()}")

    # --- EFFECT SCOPING: the object is still readable by its owner.
    runner_read = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert runner_read == payload, (
        "the object itself became unreadable to its owner, so nothing about the session was proven; "
        f"got {runner_read!r}")

    # --- SOLE CAUSE: remove the Deny and OLD works again; its issue instant never changed, so
    # any other cause of the denial would keep it refused.
    iam.delete_role_policy(RoleName=role_name, PolicyName=_REVOKE_POLICY_NAME)
    _poll_allowed(lambda: old_s3.get_object(Bucket=bucket, Key=key),
                  what="session OLD after the revoke policy was removed")
    old_read_restored = old_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert old_read_restored == payload, (
        "after removing the Deny the ORIGINAL session must read normally again -- that is what "
        f"confirms the policy was the sole cause of the denial; got {old_read_restored!r}")

    # --- and only that one inline policy is gone; the grant that made the read possible is intact.
    remaining = set()
    for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
        remaining.update(page.get("PolicyNames", []))
    assert remaining == {"sim2real-behav-inline"}, (
        "after the revoke policy was removed the role must still carry exactly its original grant; "
        f"inline policies are now {sorted(remaining)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
