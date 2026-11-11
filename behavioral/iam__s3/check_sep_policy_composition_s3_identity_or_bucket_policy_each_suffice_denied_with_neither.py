"""sep-policy-composition-s3-identity-or-bucket-policy-each-suffice-denied-with-neither."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-s3-identity-or-bucket-policy-each-suffice-denied-with-neither"
GROUP = "auth_enforcement"
SERVICES = ["iam", "s3"]


# ===== helpers =====
def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _outcome(fn):
    """'OK' when the real signed call succeeds, else its exact AWS error code."""
    code = _error_code(fn)
    return "OK" if code == "UNEXPECTED_SUCCESS" else code


def _client_as(ctx, key_id, secret, service="iam"):
    """A client signing as the minted principal."""
    return ctx.client(service, creds={"aws_access_key_id": key_id, "aws_secret_access_key": secret})


def _settle(probe, want, *, description, streak=3, timeout_s=150, interval_s=2):
    """Poll until probe() returns `want` on `streak` consecutive calls; returns every observation.

    IAM is eventually consistent; a streak keeps one lagging replica from reading as steady state.
    """
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-12:]!r}"
            )
        time.sleep(interval_s)


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _decisions(iam, source_arn, actions, resource_arns, **kw):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=actions, ResourceArns=resource_arns, **kw
    )["EvaluationResults"]
    return {r["EvalActionName"]: r for r in results}


def _sim_settle(iam, source_arn, actions, resource_arns, want, *, description, **kw):
    """Poll the simulator until every action's EvalDecision equals `want[action]`."""
    last = {}

    def probe():
        nonlocal last
        last = _decisions(iam, source_arn, actions, resource_arns, **kw)
        return {a: last[a]["EvalDecision"] for a in actions}

    _settle(probe, want, description=description, streak=1)
    return last


def _purge_user(iam, user):
    """Undo everything a check may have hung on a user, then delete it."""
    for fn in (
        lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                 for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
        lambda: [iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]],
        lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                 for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
        lambda: [iam.remove_user_from_group(UserName=user, GroupName=g["GroupName"])
                 for g in iam.list_groups_for_user(UserName=user)["Groups"]],
        lambda: iam.delete_user_permissions_boundary(UserName=user),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)
# ===== end helpers =====


def _mint(ctx, iam, prefix, policy=None):
    name = ctx.unique_name(prefix)
    arn = iam.create_user(UserName=name)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, name))
    if policy is not None:
        iam.put_user_policy(UserName=name, PolicyName="identity", PolicyDocument=policy)
    key = iam.create_access_key(UserName=name)["AccessKey"]
    return name, arn, key


def _read(client, bucket, key):
    """("OK", body bytes) on success, else (Error.Code, Error.Message)."""
    try:
        return "OK", client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _denied_message(user_arn, bucket, key):
    """S3's exact implicit-deny message for a same-account IAM user's GetObject."""
    return (
        f"User: {user_arn} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the s3:GetObject '
        f"action"
    )


def _types(result):
    return sorted({m.get("SourcePolicyType") for m in result.get("MatchedStatements", [])})


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Same-account S3 access is granted by either the identity or the bucket policy and denied with
    neither; SimulatePrincipalPolicy with ResourcePolicy agrees with GetObject in all three cases.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    """
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sep-s3-").lower()[:63]
    obj = "composition/probe.bin"
    body = uuid.uuid4().bytes * 4
    obj_arn = f"arn:aws:s3:::{bucket}/{obj}"

    create = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create)

    def _drop_bucket():
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=bucket)
    ctx.on_cleanup(_drop_bucket)
    s3.put_object(Bucket=bucket, Key=obj, Body=body)

    ident, ident_arn, ident_key = _mint(ctx, iam, "sim2real-sep-s3-id-", _policy(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}))
    res, res_arn, res_key = _mint(ctx, iam, "sim2real-sep-s3-rp-")
    none, none_arn, none_key = _mint(ctx, iam, "sim2real-sep-s3-no-")
    as_ident = _client_as(ctx, ident_key["AccessKeyId"], ident_key["SecretAccessKey"], service="s3")
    as_res = _client_as(ctx, res_key["AccessKeyId"], res_key["SecretAccessKey"], service="s3")
    as_none = _client_as(ctx, none_key["AccessKeyId"], none_key["SecretAccessKey"], service="s3")

    def sim(arn, **kw):
        return _decisions(iam, arn, ["s3:GetObject"], [obj_arn], **kw)["s3:GetObject"]

    # --- State 1: NO bucket policy. Identity-only reads; the would-be resource-policy user cannot.
    _settle(lambda: sim(ident_arn)["EvalDecision"], "allowed",
            description="simulator: identity-policy-only user, no bucket policy", streak=1)
    s_ident0, s_res0 = sim(ident_arn), sim(res_arn)
    assert (s_ident0["EvalDecision"], _types(s_ident0)) == ("allowed", ["IAM Policy"]), f"{s_ident0!r}"
    assert s_res0["EvalDecision"] == "implicitDeny", f"no identity and no bucket policy: {s_res0!r}"
    _settle(lambda: _read(as_ident, bucket, obj)[0], "OK", description="identity-only GetObject")
    got_ident = _read(as_ident, bucket, obj)
    assert got_ident == ("OK", body), f"identity-only read must return the exact bytes; got {got_ident[0]!r}"
    # Settling on the EXACT code means a not-yet-live key (InvalidAccessKeyId) cannot pass as a denial.
    _settle(lambda: _read(as_res, bucket, obj)[0], "AccessDenied",
            description="GetObject by a user with no identity policy, before any bucket policy")
    before_code, before_message = _read(as_res, bucket, obj)
    assert before_code == "AccessDenied", (
        f"no grant anywhere must be refused exactly; got {before_code!r}: {before_message!r}"
    )
    expected = _denied_message(res_arn, bucket, obj)
    assert before_message == expected, f"expected message {expected!r}, got {before_message!r}"
    assert (s_res0["EvalDecision"] == "allowed") == (before_code == "OK"), (
        f"simulator {s_res0['EvalDecision']!r} disagrees with S3 {before_code!r} with no bucket policy"
    )

    # --- State 2: add a bucket policy naming only the second user. The toggle runs absent ->
    # present because S3 can take over 150 s to honour a bucket-policy deletion.
    bucket_policy = _policy({
        "Sid": "ResourcePolicyOnly", "Effect": "Allow", "Principal": {"AWS": res_arn},
        "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
    })
    # A just-created IAM principal can be refused as "Invalid principal" until it propagates.
    _settle(lambda: _outcome(lambda: s3.put_bucket_policy(Bucket=bucket, Policy=bucket_policy)),
            "OK", description="PutBucketPolicy naming the new user", streak=1)
    s_ident = sim(ident_arn, ResourcePolicy=bucket_policy)
    s_res = sim(res_arn, ResourcePolicy=bucket_policy)
    s_none = sim(none_arn, ResourcePolicy=bucket_policy)
    assert (s_ident["EvalDecision"], _types(s_ident)) == ("allowed", ["IAM Policy"]), (
        f"identity-only user must be allowed by its IAM Policy alone; got {s_ident!r}"
    )
    assert (s_res["EvalDecision"], _types(s_res)) == ("allowed", ["Resource Policy"]), (
        f"bucket-policy-only user must be allowed by the Resource Policy alone; got {s_res!r}"
    )
    assert s_none["EvalDecision"] == "implicitDeny", f"user with neither: {s_none!r}"

    _settle(lambda: _read(as_res, bucket, obj)[0], "OK", timeout_s=240,
            description="bucket-policy-only GetObject once the bucket policy names the user")
    got_res = _read(as_res, bucket, obj)
    assert got_res == ("OK", body), f"bucket-policy-only read must return the exact bytes; got {got_res[0]!r}"
    none_code, none_message = _read(as_none, bucket, obj)
    assert none_code == "AccessDenied", (
        f"a user granted by neither policy must be refused with exactly AccessDenied; got "
        f"{none_code!r}: {none_message!r}"
    )
    expected = _denied_message(none_arn, bucket, obj)
    assert none_message == expected, f"expected message {expected!r}, got {none_message!r}"
    after_ident = _read(as_ident, bucket, obj)
    assert after_ident == ("OK", body), f"identity half unaffected by the bucket policy; got {after_ident[0]!r}"
    simulated = {"ident": s_ident["EvalDecision"] == "allowed", "res": s_res["EvalDecision"] == "allowed",
                 "none": s_none["EvalDecision"] == "allowed"}
    enforced = {"ident": after_ident[0] == "OK", "res": got_res[0] == "OK", "none": none_code == "OK"}
    assert simulated == enforced, f"simulator {simulated!r} disagrees with S3 enforcement {enforced!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
