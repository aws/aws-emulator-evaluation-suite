"""update-subscriber-replaces-filter-configuration-whole."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-subscriber-replaces-filter-configuration-whole"
GROUP = "subscriber-update"
SERVICES = ["eventbridgev2", "iam", "sqs"]

_ACTIVE_TIMEOUT_S = 60.0


def _teardown_bus(ebv2, bus_arn: str):
    """Delete the bus, waiting out a transient CREATING/DELETING rather than hiding it."""

    def run_undo() -> None:
        deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
        while True:
            try:
                ebv2.delete_event_bus(EventBusArn=bus_arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("InvalidStateException", "ResourceInUseException"):
                    raise
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)

    return run_undo


def _wait_bus_active(ebv2, bus_arn: str) -> None:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == "ACTIVE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r}, never reached ACTIVE")
        time.sleep(2)


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-ebv2-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn}]})})
    return url, arn


def _create_role(ctx, queue_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-ebv2-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="send-to-queue", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="send-to-queue"))
    return arn


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSubscriber's FilterConfiguration replaces the whole stored filter list: supplying
    one filter drops every filter not named, and an empty FilterConfiguration clears all of them.

    Reference: https://docs.aws.amazon.com/eventbridgev2/latest/APIReference/API_UpdateSubscriber.html
    """
    ebv2 = ctx.client("eventbridgev2")

    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    sub_name = ctx.unique_name("sim2real-behav-ebv2-sub-")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_role(ctx, queue_arn)

    data_pattern = json.dumps({"detail": {"kind": ["a"]}})
    meta_pattern = json.dumps({"region": ["west"]})

    sub = ebv2.create_subscriber(
        Name=sub_name, EventBusArn=bus_arn, ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        InvokeConfiguration={"RoleArn": role_arn, "TargetArn": queue_arn, "SqsParameters": {}},
        FilterConfiguration={"Filters": [
            {"Scope": "DATA", "Pattern": data_pattern},
            {"Scope": "METADATA", "Pattern": meta_pattern},
        ]},
    )
    sub_arn = sub["SubscriberArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ebv2.delete_subscriber(SubscriberArn=sub_arn)))
    assert sub["State"] == "RUNNING", f"expected a fresh subscriber to be RUNNING, got {sub['State']!r}"

    created = ebv2.describe_subscriber(SubscriberArn=sub_arn)
    created_scopes = {f["Scope"] for f in created["FilterConfiguration"]["Filters"]}
    assert created_scopes == {"DATA", "METADATA"}, (
        f"freshly created subscriber's filter scopes were {sorted(created_scopes)}, "
        f"expected DATA and METADATA"
    )

    ebv2.update_subscriber(
        SubscriberArn=sub_arn,
        FilterConfiguration={"Filters": [{"Scope": "DATA", "Pattern": data_pattern}]},
    )
    after_narrow = ebv2.describe_subscriber(SubscriberArn=sub_arn)
    narrow_filters = after_narrow["FilterConfiguration"]["Filters"]
    assert len(narrow_filters) == 1, (
        f"after replacing with one DATA filter, DescribeSubscriber listed {narrow_filters!r}, "
        f"expected exactly one"
    )
    assert narrow_filters[0]["Scope"] == "DATA", (
        f"the surviving filter's Scope was {narrow_filters[0]['Scope']!r}, expected 'DATA'"
    )
    assert narrow_filters[0]["Pattern"] == data_pattern, (
        f"the surviving filter's Pattern was {narrow_filters[0]['Pattern']!r} != {data_pattern!r}"
    )

    ebv2.update_subscriber(SubscriberArn=sub_arn, FilterConfiguration={})
    after_clear = ebv2.describe_subscriber(SubscriberArn=sub_arn)
    cleared_filters = after_clear.get("FilterConfiguration", {}).get("Filters", [])
    assert cleared_filters == [], (
        f"after UpdateSubscriber with an empty FilterConfiguration, DescribeSubscriber still "
        f"listed {cleared_filters!r}, expected none"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
