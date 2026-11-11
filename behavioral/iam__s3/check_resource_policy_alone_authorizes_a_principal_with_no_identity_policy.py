"""resource-policy-alone-authorizes-a-principal-with-no-identity-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-alone-authorizes-a-principal-with-no-identity-policy"
GROUP = "auth_enforcement"
SERVICES = ["iam", "s3"]

_IDENTITY = "sim2real-behav-union-identity-grant"
_LIST_ONLY = "sim2real-behav-union-list-only"
_BODY = b"sim2real-union-rule-payload-0123456789"
_MARK = [{"Key": "sim2real", "Value": CHECK}]
_NO_POLICY = ("NoSuchBucketPolicy", "The bucket policy does not exist")


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Within one account identity and resource policies UNION: a user with no s3:GetObject grant reads
    the object because the bucket policy names it, is refused with AccessDenied once that policy is
    deleted (the owner still reads), and an identity-policy grant alone authorizes it again."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-union-")
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _MARK})

    key_name = "sim2real/union/payload.bin"
    s3.put_object(Bucket=bucket, Key=key_name, Body=_BODY)
    ctx.on_cleanup(lambda: _drop_object(s3, bucket, key_name))
    object_arn = f"arn:aws:s3:::{bucket}/{key_name}"

    user = ctx.unique_name("sim2real-union-user-")
    iam.create_user(UserName=user, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    # The ONLY identity grant the user starts with is s3:ListAllMyBuckets, whose resource
    # (arn:aws:s3:::*) cannot overlap an object, so it can never authorize GetObject. It exists as the
    # credential-health control: without it a refusal below is indistinguishable from a dead key.
    iam.put_user_policy(
        UserName=user,
        PolicyName=_LIST_ONLY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:ListAllMyBuckets",
                "Resource": "arn:aws:s3:::*",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_LIST_ONLY))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _signing_as(ctx, "s3", key)

    ready = _poll(
        lambda: _outcome(lambda: as_user.list_buckets()),
        lambda o: o == "OK",
        timeout_s=240,
        interval_s=5,
        description="the s3:ListAllMyBuckets grant becomes effective for the minted key",
    )
    assert ready == "OK", (
        f"the credential-health control must pass before any GetObject refusal is attributed to "
        f"policy; expected 'OK', got {ready!r}"
    )

    # --- Leg 1: NEITHER policy grants the object. The baseline refusal.
    denied = (
        "AccessDenied",
        f"User: {user_arn} is not authorized to perform: s3:GetObject on resource: "
        f"\"{object_arn}\" because no identity-based policy allows the s3:GetObject action",
    )
    neither = _rejected_error(lambda: as_user.get_object(Bucket=bucket, Key=key_name))
    assert neither == denied, (
        f"with no identity grant for s3:GetObject and no bucket policy at all, the real signed "
        f"GetObject must be refused with exactly {denied!r}; got {neither!r}"
    )

    # --- Leg 2: the BUCKET POLICY alone. No identity grant is added.
    _put_bucket_policy(s3, bucket, {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ResourcePolicyOnly",
            "Effect": "Allow",
            "Principal": {"AWS": user_arn},
            "Action": "s3:GetObject",
            "Resource": object_arn,
        }],
    }, timeout_s=_budget_s(ctx, 90.0))
    ctx.on_cleanup(lambda: _drop_bucket_policy(s3, bucket))
    inline = [
        n
        for page in iam.get_paginator("list_user_policies").paginate(UserName=user)
        for n in page["PolicyNames"]
    ]
    assert inline == [_LIST_ONLY], (
        f"the user must hold ONLY the ListAllMyBuckets policy while the bucket policy is the sole "
        f"grant, or this leg proves nothing about the union; expected [{_LIST_ONLY!r}], the "
        f"paginated ListUserPolicies reports {inline!r}"
    )
    body = _poll(
        lambda: _read_body(as_user, bucket, key_name),
        lambda b: b == _BODY,
        timeout_s=240,
        interval_s=5,
        description="the bucket policy alone authorizes GetObject and the real bytes come back",
    )
    assert body == _BODY, (
        f"the bucket policy names this principal and the object, and no identity policy grants "
        f"s3:GetObject, so the union rule must permit the read and return the exact bytes written: "
        f"expected {_BODY!r}, got {body!r} -- an emulator that consults only identity policies is "
        f"refused here"
    )

    # --- Leg 3: delete ONLY the bucket policy. Nothing else moves.
    s3.delete_bucket_policy(Bucket=bucket)
    gone = _rejected_error(lambda: s3.get_bucket_policy(Bucket=bucket))
    assert gone == _NO_POLICY, (
        f"the bucket policy must be observably gone before its removal's effect is asserted; "
        f"GetBucketPolicy reported {gone!r}"
    )
    revoked = _poll(
        lambda: _outcome(lambda: as_user.get_object(Bucket=bucket, Key=key_name)),
        lambda o: o == "AccessDenied",
        timeout_s=240,
        interval_s=5,
        description="deleting the bucket policy revokes the read it was the only source of",
    )
    assert revoked == "AccessDenied", (
        f"with the bucket policy deleted the principal has no grant from either side, so the "
        f"identical real signed GetObject must be refused with exactly AccessDenied; got {revoked!r}"
    )
    revoked_error = _rejected_error(lambda: as_user.get_object(Bucket=bucket, Key=key_name))
    assert revoked_error == denied, (
        f"the revoked read must be refused with exactly {denied!r}; got {revoked_error!r}"
    )
    # Twin control in the same instant: the object is intact and readable by the owner, so the
    # refusal is authorization and not a vanished object.
    owner_body = s3.get_object(Bucket=bucket, Key=key_name)["Body"].read()
    assert owner_body == _BODY, (
        f"the bucket owner must still read the same bytes while the minted principal is refused, "
        f"proving the object survived: expected {_BODY!r}, got {owner_body!r}"
    )

    # --- Leg 4: the OTHER arm of the union. An identity policy alone, with no bucket policy.
    iam.put_user_policy(
        UserName=user,
        PolicyName=_IDENTITY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": object_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: _drop_user_policy(iam, user, _IDENTITY))
    still_no_policy = _rejected_error(lambda: s3.get_bucket_policy(Bucket=bucket))
    assert still_no_policy == _NO_POLICY, (
        f"the bucket must still carry no resource policy while the identity policy is the sole "
        f"grant, or this leg cannot distinguish the two arms; GetBucketPolicy reported "
        f"{still_no_policy!r}"
    )
    identity_body = _poll(
        lambda: _read_body(as_user, bucket, key_name),
        lambda b: b == _BODY,
        timeout_s=240,
        interval_s=5,
        description="an identity policy alone authorizes GetObject with no bucket policy present",
    )
    assert identity_body == _BODY, (
        f"the identity policy alone must authorize the read and return the exact bytes: expected "
        f"{_BODY!r}, got {identity_body!r} -- an emulator that requires a resource policy for every "
        f"object (the cross-account rule applied to a same-account request) is refused here"
    )


# ===== helpers =====
def _outcome(fn):
    """``"OK"`` on success, else the AWS error code.

    ``"OK"`` is a truthy sentinel no AWS error code can equal, and every caller either feeds it to
    ``_poll`` (which RAISES on timeout, so a target that never converges cannot pass) or asserts it
    against an exact expected value. Refusals asserted WITHOUT a preceding poll go through
    ``_rejected_error``, which raises on an unexpected success.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _rejected_error(fn):
    """``(code, message)`` of a call real AWS MUST refuse; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code") or "NO_ERROR_CODE", err.get("Message"))
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline. RAISES on timeout -- never returns its last value on failure.

    An IAM policy write reaching the S3 authorizer is genuinely asynchronous: the two services keep
    separate replicas and neither reports the propagation as done.
    """
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _signing_as(ctx, service, key):
    """A client for ``service`` signing as the principal that owns ``key``.

    ``ctx.client(..., creds=...)`` is the engine's re-signing idiom: it keeps THIS target's
    endpoint, region and TLS settings, so the second hop can never reach real AWS by accident.
    """
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _read_body(client, bucket, key_name):
    """The object's bytes, or the error code as a bytes-incompatible marker for the poll predicate.

    The predicate demands equality with the written payload, so an error can never satisfy it and the
    poll's timeout RAISES -- an error is never mistaken for a body.
    """
    try:
        return client.get_object(Bucket=bucket, Key=key_name)["Body"].read()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"


def _create_bucket(ctx, s3, bucket):
    """Create the bucket in the runner's region.

    The region fork is required by the S3 API itself -- CreateBucket refuses a
    CreateBucketConfiguration naming us-east-1 and requires one everywhere else -- and BOTH arms
    create the bucket, so no assertion is guarded by it.
    """
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.get_waiter("bucket_exists").wait(Bucket=bucket, WaiterConfig={"Delay": 2, "MaxAttempts": 30})


def _put_bucket_policy(s3, bucket, document, *, timeout_s=90, interval_s=3):
    """Attach the bucket policy, retrying only the just-created-principal race.

    S3 validates the Principal against IAM and answers MalformedPolicy ("Invalid principal in
    policy") until a freshly created user has propagated. That single code is retried; anything else
    raises immediately, and a timeout raises rather than proceeding.
    """
    deadline = time.monotonic() + timeout_s
    body = json.dumps(document)
    last = None
    while True:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=body)
            return
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last != "MalformedPolicy":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"PutBucketPolicy naming the freshly created principal never stopped reporting "
                    f"{last!r} within {timeout_s}s"
                ) from exc
            time.sleep(interval_s)


def _drop_bucket_policy(s3, bucket):
    """Teardown-only: the body deletes the policy itself, so tolerate it already being gone."""
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchBucketPolicy", "NoSuchBucket"):
            raise


def _drop_user_policy(iam, user, policy_name):
    """Teardown-only: tolerate the inline policy already being absent. Scoped to this one name."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _drop_object(s3, bucket, key_name):
    """Teardown-only, scoped to the ONE key this check wrote -- never a prefix sweep."""
    try:
        s3.delete_object(Bucket=bucket, Key=key_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _drop_bucket(s3, bucket):
    """Teardown-only: delete the bucket this check created, tolerating it already being gone."""
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
