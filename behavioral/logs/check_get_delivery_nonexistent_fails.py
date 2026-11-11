"""get-delivery-nonexistent-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-delivery-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDelivery for an unknown delivery id raises ResourceNotFoundException,
    not a generic error — and, via a positive control on a real delivery, this is
    a rejection of the unknown id specifically, not GetDelivery failing outright."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-gdnf-")[:63].rstrip("-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    source_name = ctx.unique_name("sim2real-behav-gdnf-src-")
    logs.put_delivery_source(
        name=source_name,
        resourceArn=f"arn:aws:s3:::{bucket}",
        logType="S3_SERVER_ACCESS_LOGS",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_source(name=source_name))

    target_group = ctx.unique_name("sim2real-behav-gdnf-lg-")
    logs.create_log_group(logGroupName=target_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=target_group))
    target_arn = logs.describe_log_groups(logGroupNamePrefix=target_group)["logGroups"][0]["logGroupArn"]

    dest_name = ctx.unique_name("sim2real-behav-gdnf-dst-")
    dest_resp = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": target_arn},
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))
    dest_arn = dest_resp["deliveryDestination"]["arn"]

    create_resp = logs.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=dest_arn)
    real_id = create_resp["delivery"]["id"]
    ctx.on_cleanup(lambda: logs.delete_delivery(id=real_id))

    # Positive control: GetDelivery on the real id must succeed, proving the
    # operation itself works on this account before the negative is trusted.
    got = logs.get_delivery(id=real_id)
    assert got["delivery"]["id"] == real_id, f"expected positive control to return {real_id}, got {got['delivery']}"

    bogus_id = "sim2realnonexistentdeliveryid00000000"
    code, message = _error(lambda: logs.get_delivery(id=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "Requested Delivery does not exist in this account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
