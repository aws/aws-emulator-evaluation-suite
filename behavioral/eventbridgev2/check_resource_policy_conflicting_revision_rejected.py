"""resource-policy-conflicting-revision-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-conflicting-revision-rejected"
GROUP = "resource-policy"
SERVICES = ["eventbridgev2"]

_ACTIVE_TIMEOUT_S = 60.0


def _error_code_and_message(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a stale ExpectedRevisionId is rejected, and the stored policy
    keeps its original document and revision rather than being overwritten.
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    original = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Original",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "events:PutEvents",
            "Resource": bus_arn,
        }],
    }
    put = ebv2.put_resource_policy(ResourceArn=bus_arn, PolicyDocument=json.dumps(original))
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: ebv2.delete_resource_policy(ResourceArn=bus_arn)
    ))

    replacement = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Replacement",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "events:PutEvents",
            "Resource": bus_arn,
        }],
    }
    code, message = _error_code_and_message(lambda: ebv2.put_resource_policy(
        ResourceArn=bus_arn, PolicyDocument=json.dumps(replacement),
        ExpectedRevisionId="sim2real-behav-stale-revision-id",
    ))
    assert code == "ConflictException", (
        f"expected ConflictException for a stale ExpectedRevisionId, got {code}: {message!r}"
    )
    assert message == (
        "The resource policy revision does not match ExpectedRevisionId, or the event bus was "
        "recreated since that revision was read. Re-read the policy and re-evaluate before "
        "retrying. A recent policy change can take up to a minute to be reflected on all "
        "endpoints, so a read taken immediately after one may still return the earlier revision."
    ), f"unexpected message {message!r}"

    survivor = ebv2.get_resource_policy(ResourceArn=bus_arn)
    assert survivor["RevisionId"] == put["RevisionId"], (
        f"a rejected PutResourcePolicy must not advance the revision: expected "
        f"{put['RevisionId']!r}, got {survivor['RevisionId']!r}"
    )
    assert json.loads(survivor["PolicyDocument"]) == original, (
        f"a rejected PutResourcePolicy must not change the stored document: expected "
        f"{original!r}, got {json.loads(survivor['PolicyDocument'])!r}"
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
