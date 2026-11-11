"""assumed-role-permissions-policy-requestedregion-condition-gates-put-object-by-region."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assumed-role-permissions-policy-requestedregion-condition-gates-put-object-by-region"
GROUP = "overly-permissive"
SERVICES = ["iam", "s3", "sts"]

_SUCCEEDED = object()


def _other_region(region: str) -> str:
    """The second region, derived from the runner's so the pair never collapses to one. Never
    us-east-1, whose S3 CreateBucket takes no LocationConstraint and would hide a constraint bug."""
    return "us-east-2" if region != "us-east-2" else "us-west-2"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An aws:RequestedRegion condition in a role's own policy is evaluated per request: one
    session's PutObject succeeds in the permitted region and fails with AccessDenied and its
    exact message in another; an unconditional policy reaches both."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    other_region = _other_region(ctx.region)

    def _client_with_credentials(service, creds, region=None):
        return ctx.client(service, region=region, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _outcome(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _SUCCEEDED

    def _error(fn):
        """``(code, message)`` of the refusal, or ``_SUCCEEDED``."""
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return _SUCCEEDED

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
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
        return _poll(lambda: _outcome(fn), lambda c: c is _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        return _poll(lambda: _outcome(fn), lambda c: c == expected,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became refused with {expected}")

    def _wait_creds_active(creds):
        probe = _client_with_credentials("sts", creds)
        _poll(lambda: _outcome(lambda: probe.get_caller_identity()), lambda c: c is _SUCCEEDED,
              timeout_s=180.0, interval_s=2.0,
              description="temporary credentials became active")

    def _tags_kv(scenario):
        return [{"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real", "Value": scenario}]

    def _allow(actions, resource, condition=None):
        stmt = {"Effect": "Allow", "Action": actions, "Resource": resource}
        if condition:
            stmt["Condition"] = condition
        return {"Version": "2012-10-17", "Statement": [stmt]}

    def _drop_role(role_name):
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
        _poll(lambda: _outcome(lambda: iam.get_role(RoleName=role_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"role {role_name} disappeared")

    def _drop_bucket(bucket, client):
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=obj["Key"])
        client.delete_bucket(Bucket=bucket)
        _poll(lambda: _outcome(lambda: client.head_bucket(Bucket=bucket)),
              lambda code: code in {"404", "NoSuchBucket"}, timeout_s=90.0, interval_s=2.0,
              description=f"bucket {bucket} disappeared")

    def _new_bucket(scenario, client, region):
        bucket = ctx.unique_name("sim2real-xsvc-reqreg-")
        params = {"Bucket": bucket}
        if region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": region}
        client.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(bucket, client))
        client.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _try_assume(client, role_arn, session_name, **kw):
        """The AssumeRole response on success, or the error CODE string on failure."""
        try:
            return client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **kw)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, session_name, **kw):
        return _poll(lambda: _try_assume(client, role_arn, session_name, **kw),
                     lambda r: isinstance(r, dict),
                     timeout_s=240.0, interval_s=3.0,
                     description=f"role {role_arn} became assumable")

    scenario = "iam-sts-role-policy-requestedregion"
    account = ctx.account
    payload = b"role-policy-region-scoped"
    home_key = "role-policy-region/home-write.bin"
    away_key = "role-policy-region/away-denied-write.bin"
    control_key = "role-policy-region/away-control-write.bin"

    away_s3_owner = ctx.client("s3", region=other_region)
    home_bucket = _new_bucket(scenario, s3, ctx.region)
    away_bucket = _new_bucket(scenario, away_s3_owner, other_region)

    home_region_reported = s3.get_bucket_location(
        Bucket=home_bucket).get("LocationConstraint") or "us-east-1"
    away_region_reported = away_s3_owner.get_bucket_location(
        Bucket=away_bucket).get("LocationConstraint") or "us-east-1"
    assert home_region_reported == ctx.region, (
        f"the home bucket is not in {ctx.region!r}: GetBucketLocation reports "
        f"{home_region_reported!r}")
    assert away_region_reported == other_region, (
        f"the away bucket is not in {other_region!r}: GetBucketLocation reports "
        f"{away_region_reported!r}")

    arns = [f"arn:aws:s3:::{home_bucket}/*", f"arn:aws:s3:::{away_bucket}/*"]

    role_name = ctx.unique_name("sim2real-xsvc-reqreg-role-")
    role_trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": ["sts:AssumeRole"]}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(role_trust),
        MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))

    # --- The policy under test lives on the ROLE ITSELF -- no session policy is ever passed to
    # AssumeRole in this check. s3:PutObject is granted on both buckets ONLY when the request's
    # own region equals the runner's region.
    region_scoped_policy = _allow(
        ["s3:PutObject", "s3:GetObject"], arns,
        condition={"StringEquals": {"aws:RequestedRegion": ctx.region}})
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-xsvc-region-scoped",
                        PolicyDocument=json.dumps(region_scoped_policy))

    session_name = ctx.unique_name("sim2real-xsvc-sess-")
    session = _wait_assumable(sts, role_arn, session_name)
    _wait_creds_active(session["Credentials"])
    home = _client_with_credentials("s3", session["Credentials"])
    away = _client_with_credentials("s3", session["Credentials"], region=other_region)

    # --- Both legs are the SAME session, asserted first: the divergence below is a statement
    # about the request's region, not about which of two sessions made it.
    home_ident = _client_with_credentials("sts", session["Credentials"]).get_caller_identity()
    away_ident = _client_with_credentials(
        "sts", session["Credentials"], region=other_region).get_caller_identity()
    assert home_ident["UserId"] == away_ident["UserId"], (
        "both attempts must be made by the SAME session or the comparison is meaningless; the "
        f"two region-pinned clients report {home_ident['UserId']!r} and {away_ident['UserId']!r}")

    # --- POSITIVE half: the permitted region round-trips real bytes.
    _poll_allowed(lambda: home.put_object(Bucket=home_bucket, Key=home_key, Body=payload),
                  what=f"s3:PutObject inside the permitted region {ctx.region}")
    home_body = home.get_object(Bucket=home_bucket, Key=home_key)["Body"].read()
    assert home_body == payload, (
        f"the permitted-region round-trip failed: read back {home_body!r} instead of {payload!r}")

    # --- The same credentials, one region away: no session policy exists here, so this denial can
    # only come from the role's OWN permissions policy.
    away_code = _poll_denied(
        lambda: away.put_object(Bucket=away_bucket, Key=away_key, Body=payload), "AccessDenied",
        what=f"s3:PutObject in {other_region}, outside the role policy's aws:RequestedRegion")
    assert away_code == "AccessDenied", (
        f"a request whose region is not {ctx.region!r} must be refused by the role's own "
        f"aws:RequestedRegion condition; got {away_code!r} against a bucket in {other_region}")
    away_error = _error(lambda: away.put_object(Bucket=away_bucket, Key=away_key, Body=payload))
    expected_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: s3:PutObject on resource: \"arn:aws:s3:::{away_bucket}/"
        f"{away_key}\" because no identity-based policy allows the s3:PutObject action")
    assert away_error == ("AccessDenied", expected_message), (
        f"the region-conditioned denial must carry S3's exact AccessDenied message "
        f"{expected_message!r}; got {away_error!r}")

    # --- EFFECT ABSENT, observed with the bucket owner's identity in the away region.
    away_head_code = _outcome(lambda: away_s3_owner.head_object(Bucket=away_bucket, Key=away_key))
    assert away_head_code == "404", (
        f"the denied cross-region PutObject left an object behind at {away_key!r}: HeadObject by "
        f"the bucket owner in {other_region} returned {away_head_code!r} instead of 404")

    # --- POSITIVE CONTROL: the same role, same trust policy, with its permissions policy swapped
    # for an UNCONDITIONAL one, must reach the second region too -- proving the first denial came
    # from the condition and not from the away bucket, the away region, or the role itself.
    iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-xsvc-region-scoped")
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-xsvc-region-scoped",
                        PolicyDocument=json.dumps(_allow(["s3:PutObject", "s3:GetObject"], arns)))
    control_session = _wait_assumable(sts, role_arn, ctx.unique_name("sim2real-xsvc-sess-"))
    _wait_creds_active(control_session["Credentials"])
    control_away = _client_with_credentials(
        "s3", control_session["Credentials"], region=other_region)
    _poll_allowed(lambda: control_away.put_object(
        Bucket=away_bucket, Key=control_key, Body=payload),
        what=f"control session s3:PutObject in {other_region} with no region condition")
    control_body = control_away.get_object(Bucket=away_bucket, Key=control_key)["Body"].read()
    assert control_body == payload, (
        f"positive control: with no region condition the bucket in {other_region} must be "
        f"writable and readable by the same role; read back {control_body!r}")

    # --- The still-conditioned session (minted before the control swap) remains permitted at
    # home, so the away denial was about the request's region, not about the session going stale.
    still_home = home.get_object(Bucket=home_bucket, Key=home_key)["Body"].read()
    assert still_home == payload, (
        "after the away denial the region-scoped session must still work in its permitted "
        f"region; got {still_home!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
