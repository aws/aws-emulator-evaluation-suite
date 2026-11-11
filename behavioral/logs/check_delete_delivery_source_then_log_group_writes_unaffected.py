"""delete-delivery-source-then-log-group-writes-unaffected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-delivery-source-then-log-group-writes-unaffected"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting a delivery source (after tearing down the delivery that used it) has
    no effect on ordinary PutLogEvents/GetLogEvents traffic on the log group that
    happened to be the delivery's destination.
    """
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-dlsrc-lg")
    log_stream = ctx.unique_name("sim2real-dlsrc-ls")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]

    message_before = f"before-delivery-teardown-{ctx.unique_name('m')}"
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": message_before}],
    )
    seen_before = _poll_get_event_containing(ctx, log_group, log_stream, message_before)
    assert seen_before == message_before, f"expected to read back {message_before!r}, got {seen_before!r}"

    # Wire up a delivery that targets this same log group, then tear it all the way down.
    dest_name = ctx.unique_name("sim2real-dlsrc-dest")
    dest_arn = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
        tags={"sim2real": CHECK},
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    bucket_name = _create_s3_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    src_name = ctx.unique_name("sim2real-dlsrc-src")
    logs.put_delivery_source(
        name=src_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS", tags={"sim2real": CHECK}
    )

    delivery_id = logs.create_delivery(
        deliverySourceName=src_name, deliveryDestinationArn=dest_arn
    )["delivery"]["id"]

    logs.delete_delivery(id=delivery_id)
    logs.delete_delivery_source(name=src_name)

    # The delete is unasserted by construction unless we prove it here: the source must actually be
    # gone, not just accepted-and-ignored.
    src_gone_code, src_gone_msg = _error(lambda: logs.get_delivery_source(name=src_name))
    assert src_gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the deleted delivery source, got {src_gone_code!r}"
    )
    assert src_gone_msg == "Requested Delivery Source does not exist in this account.", (
        f"unexpected not-found message for the deleted delivery source: {src_gone_msg!r}"
    )

    # The delivery source is now gone. Confirm the log group is completely unaffected.
    message_after = f"after-delivery-teardown-{ctx.unique_name('m')}"
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": message_after}],
    )
    seen_after = _poll_get_event_containing(ctx, log_group, log_stream, message_after)
    assert seen_after == message_after, f"expected to read back {message_after!r}, got {seen_after!r}"

    # And the earlier event is still exactly as it was.
    resp = logs.get_log_events(logGroupName=log_group, logStreamName=log_stream, startFromHead=True)
    messages = [e["message"] for e in resp["events"]]
    assert message_before in messages, f"{message_before!r} missing from GetLogEvents: {messages!r}"
    assert message_after in messages, f"{message_after!r} missing from GetLogEvents: {messages!r}"


def _error(fn):
    """The (code, message) fn() raised; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _poll_get_event_containing(ctx, log_group: str, log_stream: str, correlator: str, timeout_s: float = 60.0) -> str:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.get_log_events(logGroupName=log_group, logStreamName=log_stream, startFromHead=True)
        for event in resp.get("events", []):
            if correlator in event["message"]:
                return event["message"]
        time.sleep(3)
    raise AssertionError(f"no event containing {correlator!r} appeared within {timeout_s}s")


def _create_s3_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-logs-dlsrc").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint of us-east-1; every other region
        # requires one. Not a region assumption — the branch tracks ctx.region either way.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    return bucket_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
