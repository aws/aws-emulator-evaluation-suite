"""op-contract-describeSpotDatafeedSubscription."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSpotDatafeedSubscription"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-spot-datafeed-subscription")
def run(ctx) -> None:
    """DescribeSpotDatafeedSubscription reflects the bucket/state of a subscription we
    just created, and rejects the call once no subscription exists for the account."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-spotfeed-").lower().replace("_", "-")

    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    # CreateSpotDatafeedSubscription has EC2 itself write objects into the bucket using the S3
    # "log delivery" mechanism (like S3 server access logging), which requires ACL-based grants
    # rather than a bucket policy. Since April 2023 new buckets default to Object Ownership
    # "BucketOwnerEnforced", which disables ACLs entirely -- so without these two calls every
    # CreateSpotDatafeedSubscription would permanently fail with InaccessibleStorageLocation,
    # no matter how long we retry.
    s3.put_bucket_ownership_controls(
        Bucket=bucket,
        OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]},
    )
    s3.put_bucket_acl(
        Bucket=bucket,
        GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
    )

    # Even with ACLs enabled and granted, a freshly created S3 bucket can take a few seconds to
    # become visible/usable by other services (cross-service eventual consistency), so retry past
    # a transient InaccessibleStorageLocation instead of failing on the very first attempt.
    def _create_subscription():
        return ec2.create_spot_datafeed_subscription(Bucket=bucket, Prefix="sim2real-spotdata_")

    create_resp = _poll_until(
        _create_subscription,
        lambda resp: True,
        timeout_s=60,
        interval_s=5,
        retry_on=lambda exc: isinstance(exc, ClientError)
        and exc.response.get("Error", {}).get("Code") == "InaccessibleStorageLocation",
    )
    assert create_resp["SpotDatafeedSubscription"]["Bucket"] == bucket, (
        f"expected create response to echo bucket {bucket!r}, "
        f"got {create_resp['SpotDatafeedSubscription'].get('Bucket')!r}"
    )

    def _subscription_deleted():
        ec2.delete_spot_datafeed_subscription()

    ctx.on_cleanup(_subscription_deleted)

    resp = _poll_until(
        lambda: ec2.describe_spot_datafeed_subscription()["SpotDatafeedSubscription"],
        lambda sub: sub.get("Bucket") == bucket,
        timeout_s=30,
    )
    assert resp["State"] == "Active", f"expected Active state, got {resp['State']!r}"
    assert resp["Prefix"] == "sim2real-spotdata_", (
        f"expected Prefix 'sim2real-spotdata_', got {resp.get('Prefix')!r}"
    )

    ec2.delete_spot_datafeed_subscription()
    code, code_message = _settled_error(lambda: ec2.describe_spot_datafeed_subscription(), timeout_s=60)
    assert code == "InvalidSpotDatafeed.NotFound", (
        f"expected InvalidSpotDatafeed.NotFound after deletion, got {code!r}"
    )
    expected_code_message = "Spot datafeed subscription does not exist."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _settled_error(fn, *, timeout_s, interval_s=3.0):
    """(code, message) of the first refusal of fn() within timeout_s; a call that keeps succeeding
    raises, since a removal takes a moment to show on the next read."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected, but it kept SUCCEEDING: {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, retry_on=None):
    deadline = time.monotonic() + timeout_s
    last = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except Exception as exc:  # noqa: BLE001 - deliberately broad, re-raised below if not retryable
            if retry_on is not None and retry_on(exc):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    if last_exc is not None and last is None:
        raise last_exc
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
