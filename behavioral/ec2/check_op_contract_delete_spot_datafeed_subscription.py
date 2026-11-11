"""op-contract-delete-spot-datafeed-subscription."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-delete-spot-datafeed-subscription"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-spot-datafeed-subscription")
def run(ctx) -> None:
    """DeleteSpotDatafeedSubscription actually removes the account-level subscription
    (subsequent Describe raises NotFound); DryRun rejects without deleting."""

    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-spotfeed-").replace("_", "-")
    try:
        # S3 CreateBucket rejects an explicit LocationConstraint of us-east-1 itself (that
        # region is the one case where omitting the member is the only legal request shape).
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": ctx.region},
            )
    except Exception as exc:  # pragma: no cover - environment-dependent
        raise AssertionError(f"could not create S3 bucket for datafeed: {exc}") from exc
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "delete-spot-datafeed-subscription-contract"}]},
    )

    # EC2 writes the data feed to the bucket via the S3 "Log Delivery" system group, not the
    # caller's own identity. The bucket must explicitly grant that group WRITE/READ_ACP via an ACL
    # (and, buckets default to ACLs-disabled Object Ownership, which must be relaxed first) or
    # CreateSpotDatafeedSubscription fails with InaccessibleStorageLocation.
    try:
        s3.put_bucket_ownership_controls(
            Bucket=bucket,
            OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]},
        )
        s3.put_bucket_acl(
            Bucket=bucket,
            GrantWrite="URI=http://acs.amazonaws.com/groups/s3/LogDelivery",
            GrantReadACP="URI=http://acs.amazonaws.com/groups/s3/LogDelivery",
        )
    except Exception as exc:  # pragma: no cover - environment-dependent
        raise AssertionError(f"could not grant S3 log-delivery ACL on bucket: {exc}") from exc

    ec2.create_spot_datafeed_subscription(Bucket=bucket)
    ctx.on_cleanup(lambda: _best_effort_delete_subscription(ec2))

    sub = ec2.describe_spot_datafeed_subscription()["SpotDatafeedSubscription"]
    assert sub["Bucket"] == bucket, f"expected bucket {bucket!r}, got {sub.get('Bucket')!r}"
    assert sub["State"] in ("Active", "Inactive"), f"unexpected State {sub.get('State')!r}"

    # Error boundary: DryRun must short-circuit with DryRunOperation and NOT delete.
    code, msg = _client_error(lambda: ec2.delete_spot_datafeed_subscription(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    still_there = ec2.describe_spot_datafeed_subscription()["SpotDatafeedSubscription"]
    assert still_there["Bucket"] == bucket, "DryRun must not have deleted the subscription"

    # Success path: real delete removes the subscription; subsequent Describe is NotFound.
    # NOTE: DeleteSpotDatafeedSubscription's real response has no "Return" member (it is an
    # empty result besides the request ID) -- the actual effect is verified via the follow-up
    # Describe call, which must now report NotFound. The removal of this account-level
    # singleton is not always visible on the very next call (a Describe issued immediately
    # after Delete can still transiently report the subscription, or surface a different
    # transient error) so poll for the settled NotFound error rather than checking once.
    ec2.delete_spot_datafeed_subscription()

    _poll_until(
        lambda: _outcome(lambda: ec2.describe_spot_datafeed_subscription()),
        lambda outcome: outcome[0] == "InvalidSpotDatafeed.NotFound",
        timeout_s=60,
        interval_s=3,
    )
    code, msg = _client_error(lambda: ec2.describe_spot_datafeed_subscription())
    assert code == "InvalidSpotDatafeed.NotFound", f"got {code!r}"
    expected_msg = "Spot datafeed subscription does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Deleting again when none exists is idempotent-success per the documented contract.
    ec2.delete_spot_datafeed_subscription()


def _best_effort_delete_subscription(ec2: Any) -> None:
    ec2.delete_spot_datafeed_subscription()


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _outcome(fn: Callable[[], Any]) -> tuple[str, str]:
    """``(code, message)`` of a refused call, or ``("Succeeded", "")`` for a poll probe."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    return "Succeeded", ""


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
