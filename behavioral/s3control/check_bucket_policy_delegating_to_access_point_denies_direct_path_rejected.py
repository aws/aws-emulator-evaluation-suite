"""bucket-policy-delegating-to-access-point-denies-direct-path-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-policy-delegating-to-access-point-denies-direct-path-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]

#: Resource-policy evaluation is effective in seconds. The bound exists so the poll RAISES; the
#: real barrier is the twin control read on the access-point path inside the same loop.
_POLICY_EFFECTIVE_TIMEOUT_S = 60.0
#: The same bound for the reverse transition once the policy is removed.
_POLICY_REMOVED_TIMEOUT_S = 60.0

_KEY = "shared/report.txt"
_BODY = b"reachable-only-through-the-access-point"
# HeadObject has no body, so botocore may report the refusal as "403" instead of AccessDenied.
_DENIED_CODES = ("AccessDenied", "403")


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A bucket policy Deny on null s3:DataAccessPointArn refuses direct GetObject/HeadObject while
    the access-point path keeps serving the object; deleting the policy restores the direct path."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    identity = ctx.client("sts").get_caller_identity()
    account = identity["Account"]
    bucket = ctx.unique_name("sim2real-behav-apdel-")
    name = ctx.unique_name("sim2real-behav-apdl-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    # Registered after the bucket teardown so LIFO cleanup drops the policy first.
    ctx.on_cleanup(lambda: _drop_bucket_policy(s3, bucket))
    s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY)

    ap_arn = s3c.create_access_point(AccountId=account, Name=name, Bucket=bucket)[
        "AccessPointArn"
    ]
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, name))
    assert s3c.get_access_point(AccountId=account, Name=name)["Bucket"] == bucket, (
        f"GetAccessPoint does not report {name!r} as fronting {bucket!r}, so the two paths below "
        "are not two paths to the same object"
    )

    # BEAT 1 — positive control. Both paths read the object before anything is broken, so the
    # refusal below cannot be "this target denies every GetObject".
    direct_before = s3.get_object(Bucket=bucket, Key=_KEY)["Body"].read()
    assert direct_before == _BODY, (
        f"the direct bucket path read {direct_before!r} before any policy, expected {_BODY!r}"
    )
    ap_before = s3.get_object(Bucket=ap_arn, Key=_KEY)["Body"].read()
    assert ap_before == _BODY, (
        f"the access point path read {ap_before!r} before any policy, expected {_BODY!r}"
    )

    # BEAT 2 — break exactly one thing: deny GetObject unless the request arrived through an
    # access point. Only access-point requests carry s3:DataAccessPointArn, so the Null
    # condition matches the direct path alone.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyDirectObjectReads",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"Null": {"s3:DataAccessPointArn": "true"}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    # BEAT 3 — the specific refusal on the direct path, with the access-point path re-read on
    # every iteration as a same-instant twin control: a target that closes BOTH paths, or
    # that has no policy evaluation and closes NEITHER, is separated from real AWS here.
    denied_code, denied_message = _poll_direct_denied(s3, bucket, ap_arn)
    assert denied_code in _DENIED_CODES, (
        f"GetObject on the direct bucket path returned {denied_code!r} once the delegating "
        f"policy was in place, expected one of {_DENIED_CODES!r}"
    )
    want = (
        f"User: {identity['Arn']} is not authorized to perform: s3:GetObject on resource: "
        f"\"arn:aws:s3:::{bucket}/{_KEY}\" with an explicit deny in a resource-based policy"
    )
    if denied_code == "AccessDenied":
        assert denied_message == want, (
            f"GetObject on the direct bucket path said {denied_message!r}, expected {want!r}"
        )

    # BEAT 4 — effect absent, via a DIFFERENT operation than the one already refused, and the
    # access-point path proven still open by the same pair of operations.
    head_code, head_message = _error_code(lambda: s3.head_object(Bucket=bucket, Key=_KEY))
    assert head_code in _DENIED_CODES, (
        f"HeadObject on the direct bucket path returned {head_code!r} while GetObject was "
        f"refused with {denied_code!r}; expected the delegation Deny to cover both"
    )
    assert head_message == "Forbidden", (
        f"HeadObject on the direct bucket path said {head_message!r}, expected 'Forbidden'"
    )
    ap_head = s3.head_object(Bucket=ap_arn, Key=_KEY)
    assert ap_head["ContentLength"] == len(_BODY), (
        f"HeadObject through the access point reports ContentLength "
        f"{ap_head['ContentLength']!r}, expected {len(_BODY)} — the delegating policy must not "
        "narrow the access-point path"
    )
    ap_during = s3.get_object(Bucket=ap_arn, Key=_KEY)["Body"].read()
    assert ap_during == _BODY, (
        f"the access point path read {ap_during!r} while the direct path was denied, expected "
        f"{_BODY!r}: the policy delegates access control, it does not remove it"
    )

    # The object itself is untouched — the Deny is an authorization verdict, not a mutation.
    listed = {o["Key"] for o in s3.list_objects_v2(Bucket=bucket)["Contents"]}
    assert listed == {_KEY}, (
        f"the bucket lists {sorted(listed)!r} while the direct read was denied, expected exactly "
        f"{[_KEY]!r} — a GetObject Deny must not affect storage or listing"
    )

    # BEAT 5 — restore. BEAT 6 — the identical direct call succeeds again, byte for byte.
    s3.delete_bucket_policy(Bucket=bucket)
    direct_after = _poll_direct_allowed(s3, bucket)
    assert direct_after == _BODY, (
        f"after DeleteBucketPolicy the direct path read {direct_after!r}, expected the original "
        f"{_BODY!r}"
    )
    ap_after = s3.get_object(Bucket=ap_arn, Key=_KEY)["Body"].read()
    assert ap_after == _BODY, (
        f"the access point path read {ap_after!r} after the policy was removed, expected {_BODY!r}"
    )


# ===== helpers =====

def _poll_direct_denied(s3, bucket: str, ap_arn: str) -> tuple[str, str]:
    """Wait for the direct path to be refused, re-proving the access-point path each iteration;
    return the refusal's (code, message).

    Raises on timeout. The access-point read is the same-instant control: if it ever fails, the
    target has broken both paths and the caller must not read that as "the delegation worked".
    """
    deadline = time.monotonic() + _POLICY_EFFECTIVE_TIMEOUT_S
    while time.monotonic() < deadline:
        control = s3.get_object(Bucket=ap_arn, Key=_KEY)["Body"].read()
        assert control == _BODY, (
            f"the access point control read returned {control!r} while waiting for the direct "
            f"path to be denied, expected {_BODY!r} — the policy closed BOTH paths"
        )
        try:
            s3.get_object(Bucket=bucket, Key=_KEY)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(2)
    raise AssertionError(
        f"the direct bucket path was still readable {_POLICY_EFFECTIVE_TIMEOUT_S}s after a bucket "
        "policy denying every GetObject that did not arrive through an access point"
    )


def _poll_direct_allowed(s3, bucket: str) -> bytes:
    """Wait for the direct path to work again after the policy is removed. Raises on timeout."""
    deadline = time.monotonic() + _POLICY_REMOVED_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            return s3.get_object(Bucket=bucket, Key=_KEY)["Body"].read()
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            time.sleep(2)
    raise AssertionError(
        f"the direct bucket path was still refused with {last!r} "
        f"{_POLICY_REMOVED_TIMEOUT_S}s after DeleteBucketPolicy removed the only Deny"
    )


def _error_code(fn):
    """The AWS error (code, message) raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error code was expected")


def _drop_bucket_policy(s3, bucket: str) -> None:
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchBucketPolicy"):
            raise


def _drop_access_point(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAccessPoint":
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
