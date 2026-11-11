"""session-policy-region-condition-rejected-in-one-region-and-permitted-in-another."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-policy-region-condition-rejected-in-one-region-and-permitted-in-another"
GROUP = 'overly-permissive'
SERVICES = ['sts']

# A fixed second region. Not us-east-1, whose S3 CreateBucket takes no LocationConstraint.
_OTHER_REGION = "us-east-2"
# What _error_code returns when the call succeeds: equal to no AWS error code.
_SUCCEEDED = "<call succeeded>"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A session whose policy has aws:RequestedRegion writes a bucket in the permitted region and is
    AccessDenied in a second region, while a session without the condition reaches both.
    """

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # Minted credentials are never written to os.environ and never appear in assertion messages.

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
        """The error code of a failing call, or ``_SUCCEEDED`` if it succeeded."""
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
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})")
            time.sleep(interval_s)

    def _poll_allowed(fn, *, timeout_s=240.0, what="call"):
        """Poll until fn() succeeds; IAM/STS propagation is per-replica, so one success is racy."""
        return _poll(lambda: _error_code(fn), lambda c: c == _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with exactly `expected`; called only after a positive control."""
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
        """create_role, returning the Role dict or the error code.

        IAM is eventually consistent about a new role ARN as a trust principal and a freed name.
        """
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
        # Tagged so tag-based cleanup can find a bucket outside ctx.region.
        c.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _try_assume(client, role_arn, **kw):
        """The AssumeRole response on success, or the error code string on failure."""
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

    scenario = "sts-session-policy-requested-region"
    payload = b"regionally-scoped"
    home_key = "region-home-write"
    away_key = "region-away-denied-write"
    control_key = "region-away-control-write"

    assert ctx.region != _OTHER_REGION, (
        f"the runner's region is {ctx.region!r}, which is this check's designated SECOND region; the "
        "two must differ or the condition cannot discriminate anything")

    away_s3_owner = ctx.client("s3", region=_OTHER_REGION)
    home_bucket = _new_bucket(scenario)
    away_bucket = _new_bucket(scenario, client=away_s3_owner, region=_OTHER_REGION)

    home_region_reported = s3.get_bucket_location(
        Bucket=home_bucket).get("LocationConstraint") or "us-east-1"
    away_region_reported = away_s3_owner.get_bucket_location(
        Bucket=away_bucket).get("LocationConstraint") or "us-east-1"
    assert home_region_reported == ctx.region, (
        f"the home bucket is not in {ctx.region!r}: GetBucketLocation reports "
        f"{home_region_reported!r}")
    assert away_region_reported == _OTHER_REGION, (
        f"the away bucket is not in {_OTHER_REGION!r}: GetBucketLocation reports "
        f"{away_region_reported!r}")

    arns = [f"arn:aws:s3:::{home_bucket}", f"arn:aws:s3:::{home_bucket}/*",
            f"arn:aws:s3:::{away_bucket}", f"arn:aws:s3:::{away_bucket}/*"]

    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_trust_root()),
        MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    # The ROLE allows s3:* on BOTH buckets in BOTH regions, so no denial below can come from it.
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(_allow(["s3:*"], arns)))

    # Break exactly one thing: a session policy that allows the same s3:* ONLY when the request's
    # region is ctx.region.
    region_scoped_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:*"], "Resource": arns,
         "Condition": {"StringEquals": {"aws:RequestedRegion": ctx.region}}}]}

    session = _wait_assumable(sts, role_arn, Policy=json.dumps(region_scoped_policy))
    _wait_creds_active(session["Credentials"])
    home = _client_with_credentials("s3", session["Credentials"])
    away = _client_with_credentials("s3", session["Credentials"], region=_OTHER_REGION)

    # Both legs are the same session, so the divergence below is about the request.
    home_ident = _client_with_credentials("sts", session["Credentials"]).get_caller_identity()
    away_ident = _client_with_credentials(
        "sts", session["Credentials"], region=_OTHER_REGION).get_caller_identity()
    assert home_ident["UserId"] == away_ident["UserId"], (
        "both attempts must be made by the SAME session or the comparison is meaningless; the two "
        f"region-pinned clients report {home_ident['UserId']!r} and {away_ident['UserId']!r}")

    # The permitted region round-trips real bytes; this also waits out propagation.
    _poll_allowed(lambda: home.put_object(Bucket=home_bucket, Key=home_key, Body=payload),
                  what=f"s3:PutObject inside the permitted region {ctx.region}")
    home_body = home.get_object(Bucket=home_bucket, Key=home_key)["Body"].read()
    assert home_body == payload, (
        f"the permitted-region round-trip failed: read back {home_body!r} instead of {payload!r}")

    away_code = _poll_denied(
        lambda: away.put_object(Bucket=away_bucket, Key=away_key, Body=payload), "AccessDenied",
        what=f"s3:PutObject in {_OTHER_REGION}, outside aws:RequestedRegion")
    assert away_code == "AccessDenied", (
        f"a request whose region is not {ctx.region!r} must be refused by the session policy's "
        f"aws:RequestedRegion condition; got {away_code!r} against a bucket in {_OTHER_REGION}")

    # Effect absent, observed with the bucket owner's identity in the away region.
    away_head_code = _error_code(
        lambda: away_s3_owner.head_object(Bucket=away_bucket, Key=away_key))
    assert away_head_code == "404", (
        f"the denied cross-region PutObject left an object behind at {away_key!r}: HeadObject by "
        f"the bucket owner in {_OTHER_REGION} returned {away_head_code!r} instead of 404")

    # Control: the same role with no session policy reaches the second region, so the denial
    # came from the condition and not from the away bucket, region, or role.
    control_session = _wait_assumable(sts, role_arn)
    _wait_creds_active(control_session["Credentials"])
    control_away = _client_with_credentials(
        "s3", control_session["Credentials"], region=_OTHER_REGION)
    _poll_allowed(lambda: control_away.put_object(
        Bucket=away_bucket, Key=control_key, Body=payload),
        what=f"control session s3:PutObject in {_OTHER_REGION} with no session policy")
    control_body = control_away.get_object(Bucket=away_bucket, Key=control_key)["Body"].read()
    assert control_body == payload, (
        f"positive control: without the session policy the bucket in {_OTHER_REGION} must be "
        f"writable and readable by the same role; read back {control_body!r}")

    # The region-scoped session still works at home, so the session did not go stale.
    still_home = home.get_object(Bucket=home_bucket, Key=home_key)["Body"].read()
    assert still_home == payload, (
        "after the away denial the region-scoped session must still work in its permitted region; "
        f"got {still_home!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
