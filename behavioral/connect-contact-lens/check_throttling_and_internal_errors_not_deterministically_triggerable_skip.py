"""throttling-and-internal-errors-not-deterministically-triggerable-skip."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "throttling-and-internal-errors-not-deterministically-triggerable-skip"
GROUP = "error-semantics"
SERVICES = ["connect-contact-lens"]


UNAUTHORIZED = "Unauthorized"
NOT_FOUND = "Real-time contact analysis not found."


def _error(fn):
    """Call fn(); return the botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With an ACTIVE Connect instance, ListRealtimeContactAnalysisSegments fails with UnauthorizedException
    for a malformed InstanceId and ResourceNotFoundException for a made-up one or contact, each with its
    exact message, and 10 concurrent unknown-contact calls all return ResourceNotFoundException."""
    connect = ctx.client("connect")
    lens = ctx.client("connect-contact-lens")
    alias = ctx.unique_name("sim2real-behav-")

    instance = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real-check": CHECK},
    )
    instance_id = instance["Id"]
    ctx.on_cleanup(lambda: _delete_instance(connect, instance_id))
    active = _wait_for_instance_status(connect, instance_id, "ACTIVE")
    assert active["InstanceStatus"] == "ACTIVE", f"expected ACTIVE, got {active!r}"

    # (a) error body must carry real content, not just a status code, for each
    # documented client error we CAN deterministically trigger now that the account
    # has a real instance to anchor the authorization layer.
    cases = (
        (
            {"InstanceId": "\t\t", "ContactId": str(uuid.uuid4())},
            "UnauthorizedException",
            UNAUTHORIZED,
        ),
        (
            {"InstanceId": str(uuid.uuid4()), "ContactId": str(uuid.uuid4())},
            "ResourceNotFoundException",
            NOT_FOUND,
        ),
    )
    for kwargs, expected_code, expected_message in cases:
        error = _error(lambda kw=kwargs: lens.list_realtime_contact_analysis_segments(**kw))
        assert error["Code"] == expected_code, (
            f"expected {expected_code} for {kwargs}, got {error!r}"
        )
        assert error.get("Message") == expected_message, (
            f"expected Message {expected_message!r} for {expected_code}, got {error!r}"
        )

    # (b) the same contract must also hold against the REAL active instance this
    # check created, for an unknown ContactId -> ResourceNotFoundException.
    fake_contact = str(uuid.uuid4())
    error = _error(
        lambda: lens.list_realtime_contact_analysis_segments(
            InstanceId=instance_id, ContactId=fake_contact
        )
    )
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException against a real ACTIVE instance, got {error!r}"
    )
    assert error.get("Message") == NOT_FOUND, (
        f"expected Message {NOT_FOUND!r} for ResourceNotFoundException, got {error!r}"
    )

    # (c) that ResourceNotFoundException contract must hold under concurrent load too.
    def probe():
        err = _error(
            lambda: lens.list_realtime_contact_analysis_segments(
                InstanceId=instance_id, ContactId=fake_contact
            )
        )
        return err["Code"]

    with ThreadPoolExecutor(max_workers=10) as pool:
        codes = list(pool.map(lambda _: probe(), range(10)))
    assert codes == ["ResourceNotFoundException"] * 10, (
        f"inconsistent codes under concurrent load: {codes}"
    )


def _wait_for_instance_status(connect, instance_id, status, timeout_s=270.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = connect.describe_instance(InstanceId=instance_id)
        last = resp["Instance"]
        if last["InstanceStatus"] == status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} never reached {status}, last={last}")


def _delete_instance(connect, instance_id):
    try:
        connect.delete_instance(InstanceId=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
