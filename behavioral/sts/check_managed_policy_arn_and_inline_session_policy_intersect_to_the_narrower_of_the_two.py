"""managed-policy-arn-and-inline-session-policy-intersect-to-the-narrower-of-the-two."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-policy-arn-and-inline-session-policy-intersect-to-the-narrower-of-the-two"
GROUP = 'overly-permissive'
SERVICES = ['sts']

# What _outcome returns for a call that succeeded: an object no error code can equal.
_SUCCEEDED = object()


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PolicyArns and Policy on one AssumeRole union their Allows, and that set intersects the role
    policy: an action allowed by only one session document passes; one the role or the set lacks is
    AccessDenied. Controls: no session policy, then a widened role, each make the denied call pass.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session
    """

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
        """Poll until fn() SUCCEEDS. IAM/STS propagation is per-replica, so a replica that already
        holds a new key can still lack its policy; only the expected success is a safe barrier."""
        return _poll(lambda: _outcome(fn), lambda c: c is _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with EXACTLY `expected`; return the refusal's (code, message).

        Called only after a positive control proved the session live."""
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
        """As _drop_role, but a no-op if the role is already gone -- for a check that deletes the
        role itself as part of its subject. Never a bare `lambda: None`: it really does delete."""
        if _outcome(lambda: iam.get_role(RoleName=role_name)) == "NoSuchEntity":
            return
        _drop_role(role_name)

    def _try_create_role(role_name, trust_policy, scenario):
        """create_role, returning the Role dict or the error CODE. IAM is eventually consistent
        about a new role ARN as a trust-policy principal and a just-deleted name becoming free."""
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

    scenario = "sts-session-policy-set-algebra"
    bucket = _new_bucket(scenario)
    payload = b"intersect"
    read_key = "session-set-readable"
    denied_put_key = "session-set-denied-write"
    control_put_key = "session-set-control-write"
    s3.put_object(Bucket=bucket, Key=read_key, Body=payload)

    bucket_arn = f"arn:aws:s3:::{bucket}"
    objects_arn = f"arn:aws:s3:::{bucket}/*"

    # ROLE identity policy: ListBucket, GetObject, PutObject. Deliberately does NOT include
    # GetBucketTagging, which is the action both session documents will allow.
    role_doc = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": bucket_arn},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": objects_arn}]}

    # SESSION DOCUMENT A, supplied by ARN: ListBucket, GetObject, GetBucketTagging.
    managed = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-sts-pol-"),
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketTagging"],
             "Resource": bucket_arn},
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": objects_arn}]}),
        Tags=_tags_kv(scenario))["Policy"]
    managed_arn = managed["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=managed_arn))

    # SESSION DOCUMENT B, supplied inline on the same call: GetObject, GetBucketTagging.
    # It deliberately OMITS ListBucket (which A has) and PutObject (which the role has).
    inline_session_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetBucketTagging"], "Resource": bucket_arn},
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": objects_arn}]}

    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_trust_root()),
        MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(role_doc))

    scoped_session = _wait_assumable(
        sts, role_arn,
        PolicyArns=[{"arn": managed_arn}], Policy=json.dumps(inline_session_policy))
    _wait_creds_active(scoped_session["Credentials"])
    scoped = _client_with_credentials("s3", scoped_session["Credentials"])

    packed = scoped_session.get("PackedPolicySize")
    assert isinstance(packed, int) and 1 <= packed <= 100, (
        "AssumeRole must report PackedPolicySize as a 1..100 percentage whenever session policies "
        f"are supplied; got {packed!r} -- a missing value means nothing was packed")

    # --- Leg 1: the action EVERYTHING allows. This is the propagation barrier as well as the
    # data-plane round trip: until it works, no refusal below is a policy decision.
    _poll_allowed(lambda: scoped.get_object(Bucket=bucket, Key=read_key),
                  what="s3:GetObject, allowed by the role and by both session documents")
    body = scoped.get_object(Bucket=bucket, Key=read_key)["Body"].read()
    assert body == payload, (
        "the operation allowed by the role and by BOTH session documents must succeed and "
        f"round-trip its bytes; got {body!r} instead of {payload!r}")

    # --- Leg 2: allowed by session document A only. If the two documents were intersected with each
    # other this would be denied; AWS unions them, so it must succeed.
    _poll_allowed(lambda: scoped.list_objects_v2(Bucket=bucket, MaxKeys=1),
                  what="s3:ListBucket, allowed by the PolicyArns document only")
    listing = scoped.list_objects_v2(Bucket=bucket)
    assert {o["Key"] for o in listing.get("Contents", [])} == {read_key}, (
        "s3:ListBucket is allowed by the PolicyArns session document and by the role but NOT by the "
        "inline Policy document, and multiple session policies UNION their Allows, so the listing "
        f"must succeed and show exactly the seeded object; got "
        f"{sorted(o['Key'] for o in listing.get('Contents', []))!r}")

    # --- Leg 3: allowed by BOTH session documents, NOT by the role. Break exactly one thing --
    # the role's side of the intersection.
    tagging_code, tagging_message = _poll_denied(lambda: scoped.get_bucket_tagging(Bucket=bucket), "AccessDenied",
                               what="s3:GetBucketTagging, allowed by both session documents but "
                                    "not by the role")
    assert tagging_code == "AccessDenied", (
        "s3:GetBucketTagging is allowed by BOTH session documents but not by the role's identity "
        f"policy, so the intersection with the role must refuse it; got {tagging_code!r}")
    expected_tagging_message = (
        f"User: {scoped_session['AssumedRoleUser']['Arn']} is not authorized to perform: "
        f's3:GetBucketTagging on resource: "{bucket_arn}" because no identity-based policy '
        "allows the s3:GetBucketTagging action")
    assert tagging_message == expected_tagging_message, (
        f"expected the refusal message {expected_tagging_message!r}, got {tagging_message!r}")

    # --- Leg 4: allowed by the ROLE, by NEITHER session document. The session set caps at all.
    put_code, put_message = _poll_denied(
        lambda: scoped.put_object(Bucket=bucket, Key=denied_put_key, Body=payload), "AccessDenied",
        what="s3:PutObject, allowed by the role but by neither session document")
    assert put_code == "AccessDenied", (
        "s3:PutObject is allowed by the role's identity policy but by neither session document, so "
        f"the session policy set must refuse it; got {put_code!r}")
    expected_put_message = (
        f"User: {scoped_session['AssumedRoleUser']['Arn']} is not authorized to perform: "
        f's3:PutObject on resource: "arn:aws:s3:::{bucket}/{denied_put_key}" because no session '
        "policy allows the s3:PutObject action")
    assert put_message == expected_put_message, (
        f"expected the refusal message {expected_put_message!r}, got {put_message!r}")

    # --- EFFECT ABSENT, observed with the bucket owner's identity.
    head_code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=denied_put_key))
    assert head_code == "404", (
        f"the denied PutObject left an object behind at {denied_put_key!r}: HeadObject by the "
        f"bucket owner returned {head_code!r} instead of 404")

    # --- CONTROL 1 for leg 4: the same role, NO session policy. The write must succeed and
    # round-trip, which isolates the session policy set as the cause of leg 4 rather than a defect
    # in the role's own policy.
    control_session = _wait_assumable(sts, role_arn)
    _wait_creds_active(control_session["Credentials"])
    control = _client_with_credentials("s3", control_session["Credentials"])
    control_packed = control_session.get("PackedPolicySize")
    assert isinstance(control_packed, int) and 1 <= control_packed <= 100, (
        "AssumeRole reports PackedPolicySize as a 1..100 percentage even with NO session policy "
        f"supplied (measured on real AWS, us-west-2); got {control_packed!r}")
    assert packed > control_packed, (
        "the session carrying two extra policy documents must pack to a strictly larger fraction of "
        f"the limit than the session carrying none; got {packed!r} vs {control_packed!r}, which would "
        "mean the supplied session policies were not packed into the session at all")
    _poll_allowed(lambda: control.put_object(Bucket=bucket, Key=control_put_key, Body=payload),
                  what="control session s3:PutObject with no session policy")
    control_get = control.get_object(Bucket=bucket, Key=control_put_key)["Body"].read()
    assert control_get == payload, (
        "positive control: with NO session policy the write the role allows must succeed and "
        f"round-trip; the control read back {control_get!r} instead of {payload!r}")

    # --- CONTROL 2 for leg 3: widen the ROLE to include GetBucketTagging, change nothing else, and
    # re-assume with the SAME two session documents. It must now succeed, which is what makes the
    # role -- and not some property of GetBucketTagging or of the PolicyArns mechanism -- the cause
    # of leg 3's denial.
    widened = json.loads(json.dumps(role_doc))
    widened["Statement"].append(
        {"Effect": "Allow", "Action": ["s3:GetBucketTagging"], "Resource": bucket_arn})
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(widened))
    widened_session = _wait_assumable(
        sts, role_arn,
        PolicyArns=[{"arn": managed_arn}], Policy=json.dumps(inline_session_policy))
    _wait_creds_active(widened_session["Credentials"])
    widened_scoped = _client_with_credentials("s3", widened_session["Credentials"])
    _poll_allowed(lambda: widened_scoped.get_bucket_tagging(Bucket=bucket),
                  what="s3:GetBucketTagging once the ROLE also allows it")
    tag_set = {t["Key"]: t["Value"]
               for t in widened_scoped.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    assert tag_set.get("sim2real") == scenario, (
        "positive control: with the role widened, the action both session documents already allowed "
        f"must succeed and return the bucket's real tags; got {tag_set!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
