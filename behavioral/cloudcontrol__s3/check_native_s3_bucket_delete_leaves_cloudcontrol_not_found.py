"""native-s3-bucket-delete-leaves-cloudcontrol-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "native-s3-bucket-delete-leaves-cloudcontrol-not-found"
GROUP = "native-truth"
SERVICES = ["cloudcontrol", "s3"]

BUCKET_TYPE = "AWS::S3::Bucket"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A bucket created with S3's own API is visible to Cloud Control with S3's values, and once
    S3 itself deletes it Cloud Control GetResource answers ResourceNotFoundException with the
    handler's exact not-found message, not a stale success.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations.html
    """
    cc = ctx.client("cloudcontrol")
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-ccnat-").lower()

    # us-east-1 is the one region that takes no LocationConstraint.
    location = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}
    }
    s3.create_bucket(Bucket=bucket_name, **location)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket_name), "NoSuchBucket"))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    s3.get_waiter("bucket_exists").wait(Bucket=bucket_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    # ---- Cloud Control resolves a bucket it never created, with S3's own values ----------------
    described = _poll_until(
        lambda: _get_resource_or_none(cc, bucket_name),
        lambda desc: desc is not None,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to resolve {bucket_name!r}, a bucket it never created",
    )
    assert described["Identifier"] == bucket_name, (
        f"GetResource echoed Identifier {described['Identifier']!r}, expected {bucket_name!r}"
    )
    props = json.loads(described["Properties"])
    assert props.get("BucketName") == bucket_name, (
        f"Cloud Control reports BucketName {props.get('BucketName')!r}, expected {bucket_name!r}"
    )
    assert props.get("Tags") == [{"Key": "sim2real", "Value": CHECK}], (
        f"Cloud Control reports Tags {props.get('Tags')!r} for a bucket tagged natively with "
        f"sim2real={CHECK!r}"
    )

    # ---- ListResources enumerates it, paginated ---------------------------------------------
    _poll_until(
        lambda: _list_all_bucket_names(cc),
        lambda names: bucket_name in names,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"ListResources to enumerate {bucket_name!r}, a bucket Cloud Control never created",
    )

    # ---- break the one thing: S3 itself deletes the bucket, not Cloud Control -------------------
    s3.delete_bucket(Bucket=bucket_name)
    _poll_for_head_bucket_gone(
        s3,
        bucket_name,
        timeout_s=45.0,
        interval_s=2.0,
        reason=f"S3 to report {bucket_name!r} gone after its own DeleteBucket",
    )

    # ---- the effect: Cloud Control must stop vouching for a bucket S3 has deleted -------------
    cc_error = _poll_for_client_error(
        lambda: cc.get_resource(TypeName=BUCKET_TYPE, Identifier=bucket_name),
        timeout_s=45.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to report {bucket_name!r} gone after the native delete",
    )
    expected_message = _handler_not_found(
        cc_error[1], "AWS::S3::Bucket Handler returned status FAILED: Bucket not found"
    )
    assert cc_error == ("ResourceNotFoundException", expected_message), (
        f"GetResource for the natively-deleted bucket {bucket_name!r} answered {cc_error!r}, "
        f"expected ('ResourceNotFoundException', {expected_message!r}); a target that still "
        f"serves it is over-permissive"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _get_resource_or_none(cc, bucket_name):
    try:
        return cc.get_resource(TypeName=BUCKET_TYPE, Identifier=bucket_name)["ResourceDescription"]
    except ClientError:
        return None


def _list_all_bucket_names(cc):
    """Every identifier ListResources reports for AWS::S3::Bucket, across pages."""
    found: set[str] = set()
    kwargs = {"TypeName": BUCKET_TYPE}
    for _ in range(50):
        resp = cc.list_resources(**kwargs)
        found.update(d["Identifier"] for d in resp.get("ResourceDescriptions", []))
        token = resp.get("NextToken")
        if not token:
            return found
        kwargs["NextToken"] = token
    raise AssertionError(
        f"ListResources for {BUCKET_TYPE} still returned a NextToken after 50 pages "
        f"({len(found)} identifiers); pagination is not terminating"
    )


def _poll_for_head_bucket_gone(s3, bucket_name, *, timeout_s, interval_s, reason):
    """Poll head_bucket until it answers 404. RAISES when it is still succeeding at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.head_bucket(Bucket=bucket_name)
            still_there = True
        except ClientError as exc:
            status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
            if status == 404:
                return
            still_there = f"status={status}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"waited {timeout_s}s for {reason} and it never happened; last={still_there!r}")
        time.sleep(interval_s)


def _poll_for_client_error(fn, *, timeout_s, interval_s, reason):
    """Poll fn() until it raises ClientError and return its (Error.Code, Error.Message). RAISES
    when fn() is still succeeding at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason} and it never happened; last result {result!r}"
            )
        time.sleep(interval_s)


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
