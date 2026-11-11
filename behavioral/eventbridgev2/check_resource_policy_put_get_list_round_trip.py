"""resource-policy-put-get-list-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-get-list-round-trip"
GROUP = "resource-policy"
SERVICES = ["eventbridgev2"]

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
                if code != "InvalidStateException" or time.monotonic() > deadline:
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


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a bus is readable back byte-for-byte through GetResourcePolicy,
    listed by ListResourcePolicies, and gone from both after DeleteResourcePolicy.
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAccountPutEvents",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "events:PutEvents",
            "Resource": bus_arn,
        }],
    }
    put = ebv2.put_resource_policy(ResourceArn=bus_arn, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: ebv2.delete_resource_policy(ResourceArn=bus_arn)
    ))
    assert put["PolicyName"] == "default", f"expected PolicyName 'default', got {put['PolicyName']!r}"

    got = ebv2.get_resource_policy(ResourceArn=bus_arn)
    assert got["PolicyName"] == "default", f"expected PolicyName 'default', got {got['PolicyName']!r}"
    assert got["RevisionId"] == put["RevisionId"], (
        f"GetResourcePolicy revision {got['RevisionId']!r} != PutResourcePolicy revision "
        f"{put['RevisionId']!r}"
    )
    assert json.loads(got["PolicyDocument"]) == policy, (
        f"the stored document must round-trip unchanged: sent {policy!r}, got "
        f"{json.loads(got['PolicyDocument'])!r}"
    )

    pages = ebv2.get_paginator("list_resource_policies").paginate(ResourceArn=bus_arn)
    summaries = [s for page in pages for s in page["PolicySummaries"]]
    assert summaries == [{"PolicyName": "default", "RevisionId": put["RevisionId"]}], (
        f"expected exactly one 'default' policy summary at revision {put['RevisionId']!r}, "
        f"got {summaries!r}"
    )

    ebv2.delete_resource_policy(ResourceArn=bus_arn)
    code, message = _error_code_and_message(lambda: ebv2.get_resource_policy(ResourceArn=bus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "No 'default' resource policy is attached to this event bus", (
        f"unexpected message {message!r}"
    )

    pages = ebv2.get_paginator("list_resource_policies").paginate(ResourceArn=bus_arn)
    remaining = [s for page in pages for s in page["PolicySummaries"]]
    assert remaining == [], f"deleted policy still listed: {remaining!r}"


def _error_code_and_message(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
