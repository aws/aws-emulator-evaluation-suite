"""two-differently-scoped-sessions-used-concurrently-keep-their-own-authorization-outcomes."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "two-differently-scoped-sessions-used-concurrently-keep-their-own-authorization-outcomes"
GROUP = 'credential-issuance'
SERVICES = ['sts']
# What _error_code returns when the call succeeds: equal to no AWS error code.
_SUCCEEDED = "<call succeeded>"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two sessions of one role, scoped by session policy to ListBucket and GetObject, used
    concurrently for twenty rounds each keep exactly their own allow/deny outcome; no bleed-over.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session
    """

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # Minted credentials are never written to os.environ and never appear in an assertion message.

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
        """The error CODE of a failing call, or ``_SUCCEEDED`` (equal to no AWS code) if it
        succeeded, so an unexpected success never compares equal to an expected code."""
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _SUCCEEDED

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
        """Poll until fn() SUCCEEDS. IAM/STS propagation is per-replica: a replica that already
        holds a new key can still lack its policy, so a single-shot success assertion after
        polling past InvalidClientTokenId is racy -- it can pass and then transiently 403. Polling
        on the exact expected success is the only barrier that is not."""
        return _poll(lambda: _error_code(fn), lambda c: c == _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with EXACTLY `expected`. Only ever called after a positive
        control on the same session has proven the credential live, so a permissive
        implementation simply never reaches the condition and the deadline miss IS the verdict."""
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
        _poll(lambda: _error_code(lambda: iam.get_role(RoleName=role_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"role {role_name} disappeared")

    def _drop_role_if_present(role_name):
        """As _drop_role, but a no-op if the role is already gone."""
        if _error_code(lambda: iam.get_role(RoleName=role_name)) == "NoSuchEntity":
            return
        _drop_role(role_name)

    def _try_create_role(role_name, trust_policy, scenario):
        """create_role, returning the Role dict or the error CODE. IAM is eventually consistent
        about a new role ARN as a trust-policy principal and about a just-deleted name being free."""
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

    # Transient conditions that are NOT authorization decisions. Retried, never recorded as an
    # outcome -- an emulator that throttles is not an emulator that denied.
    _TRANSIENT = {"SlowDown", "503", "ServiceUnavailable", "InternalError", "RequestTimeout",
                  "Throttling", "ThrottlingException", "RequestLimitExceeded"}

    def _outcome(fn, *, attempts=6):
        """True on success, else the exact error code. Retries only transient conditions."""
        for i in range(attempts):
            try:
                fn()
                return True
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in _TRANSIENT and i < attempts - 1:
                    time.sleep(1.0 + i)
                    continue
                return code
        raise AssertionError("unreachable")

    scenario = "sts-concurrent-scoped-sessions"
    bucket = _new_bucket(scenario)
    payload = b"concurrent"
    key = "concurrent-scoped-object"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)

    bucket_arn = f"arn:aws:s3:::{bucket}"
    objects_arn = f"arn:aws:s3:::{bucket}/*"

    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_trust_root()),
        MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    # The ROLE allows both operations, so neither denial below can come from the role.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": bucket_arn},
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": objects_arn}]}))

    list_only = _wait_assumable(sts, role_arn, Policy=json.dumps(
        _allow(["s3:ListBucket"], bucket_arn)))
    get_only = _wait_assumable(sts, role_arn, Policy=json.dumps(
        _allow(["s3:GetObject"], objects_arn)))

    _wait_creds_active(list_only["Credentials"])
    _wait_creds_active(get_only["Credentials"])
    # Both clients are built BEFORE any thread starts, so the run measures the two sessions rather
    # than a race in client construction.
    list_s3 = _client_with_credentials("s3", list_only["Credentials"])
    get_s3 = _client_with_credentials("s3", get_only["Credentials"])
    list_sts = _client_with_credentials("sts", list_only["Credentials"])
    get_sts = _client_with_credentials("sts", get_only["Credentials"])

    # --- Both sessions really are distinct sessions of the same role, established before the
    # concurrent phase so a failure here is not attributed to contention.
    list_ident = list_sts.get_caller_identity()
    get_ident = get_sts.get_caller_identity()
    assert list_ident["UserId"] != get_ident["UserId"], (
        "the two sessions share a UserId, so they are not distinct sessions and the invariant below "
        f"would be vacuous: {list_ident['UserId']!r}")
    assert list_ident["Arn"].rsplit("/", 1)[0] == get_ident["Arn"].rsplit("/", 1)[0], (
        "the two sessions must come from the SAME role, or a differing outcome is explained by a "
        f"differing role rather than by the session policy: {list_ident['Arn']!r} vs "
        f"{get_ident['Arn']!r}")

    # --- PROPAGATION BARRIER: each session's permitted operation must work before any denial is
    # read as a denial. This is the bounded poll on the exact expected success, not a single shot:
    # STS/IAM propagation is per-replica, so a one-shot success can be followed by a transient 403.
    _poll_allowed(lambda: list_s3.list_objects_v2(Bucket=bucket, MaxKeys=1),
                  what="LIST-scoped session performing its permitted ListBucket")
    _poll_allowed(lambda: get_s3.get_object(Bucket=bucket, Key=key),
                  what="GET-scoped session performing its permitted GetObject")
    _poll_denied(lambda: list_s3.get_object(Bucket=bucket, Key=key), "AccessDenied",
                 what="LIST-scoped session attempting GetObject")
    _poll_denied(lambda: get_s3.list_objects_v2(Bucket=bucket, MaxKeys=1), "AccessDenied",
                 what="GET-scoped session attempting ListBucket")

    rounds_n = 20

    def _round(i):
        """One round: BOTH sessions attempt BOTH operations. Four outcomes."""
        return {
            "round": i,
            "list_by_list": _outcome(lambda: list_s3.list_objects_v2(Bucket=bucket, MaxKeys=1)),
            "get_by_list": _outcome(lambda: list_s3.get_object(Bucket=bucket, Key=key)),
            "list_by_get": _outcome(lambda: get_s3.list_objects_v2(Bucket=bucket, MaxKeys=1)),
            "get_by_get": _outcome(lambda: get_s3.get_object(Bucket=bucket, Key=key)),
        }

    with ThreadPoolExecutor(max_workers=2) as pool:
        rounds = list(pool.map(_round, range(rounds_n)))

    assert len(rounds) == rounds_n, (
        f"only {len(rounds)} of {rounds_n} rounds completed, so the invariant is under-sampled")

    bad_list_by_list = [r for r in rounds if r["list_by_list"] is not True]
    assert not bad_list_by_list, (
        f"the LIST-scoped session failed a PERMITTED ListBucket in {len(bad_list_by_list)} of "
        f"{rounds_n} rounds: {bad_list_by_list[:3]!r}")

    bad_get_by_list = [r for r in rounds if r["get_by_list"] != "AccessDenied"]
    assert not bad_get_by_list, (
        "the LIST-scoped session performed, or was refused for the wrong reason, a GetObject its "
        f"session policy excludes, in {len(bad_get_by_list)} of {rounds_n} rounds: "
        f"{bad_get_by_list[:3]!r}")

    bad_get_by_get = [r for r in rounds if r["get_by_get"] is not True]
    assert not bad_get_by_get, (
        f"the GET-scoped session failed a PERMITTED GetObject in {len(bad_get_by_get)} of "
        f"{rounds_n} rounds: {bad_get_by_get[:3]!r}")

    bad_list_by_get = [r for r in rounds if r["list_by_get"] != "AccessDenied"]
    assert not bad_list_by_get, (
        "the GET-scoped session performed, or was refused for the wrong reason, a ListBucket its "
        f"session policy excludes, in {len(bad_list_by_get)} of {rounds_n} rounds: "
        f"{bad_list_by_get[:3]!r}")

    # --- The bytes were really moving: the GET-scoped session's reads returned the payload, so
    # "success" above was a real data-plane round trip and not a 200 with an empty body.
    final_body = get_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert final_body == payload, (
        "after twenty concurrent rounds the GET-scoped session must still read the object's real "
        f"bytes; got {final_body!r} instead of {payload!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
