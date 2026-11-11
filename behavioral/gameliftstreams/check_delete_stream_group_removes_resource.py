"""delete-stream-group-removes-resource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stream-group-removes-resource"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteStreamGroup transitions the group out of existence: a subsequent GetStreamGroup
    eventually returns ResourceNotFoundException, and the dead identifier is also unusable
    for a further mutation (a second DeleteStreamGroup) rather than being silently accepted."""
    gls = ctx.client("gameliftstreams")
    try:
        group = gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen4n_high",
            LocationConfigurations=[{"LocationName": ctx.region, "MaximumCapacity": 2}],
            Tags={"sim2real-audit": "true"},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _delete_stream_group_when_settled(gls, arn))
    assert group["Status"] in ("ACTIVATING", "ACTIVE"), (
        f"expected a freshly created stream group to be ACTIVATING or ACTIVE, got {group['Status']!r}"
    )

    # DeleteStreamGroup rejects a group that is still ACTIVATING with ValidationException
    # ("is in ACTIVATING status") -- real AWS requires the group to reach a terminal ready
    # state first, so wait for that before exercising delete.
    ready = _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda r: r["Status"] not in ("ACTIVATING", "UPDATING_LOCATIONS"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert ready["Status"] == "ACTIVE", (
        f"expected the stream group to reach ACTIVE before delete, got {ready['Status']!r} "
        f"({ready.get('StatusReason')})"
    )

    gls.delete_stream_group(Identifier=arn)

    def _probe():
        try:
            return gls.get_stream_group(Identifier=arn)["Status"], None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")

    # Deprovisioning is asynchronous too: GetStreamGroup keeps answering with a transitional
    # status (e.g. DELETING) before it finally raises ResourceNotFoundException, so this needs
    # the same generous ceiling as the ACTIVATING -> ACTIVE wait above, not a short one.
    code, message = _poll_until(
        _probe,
        lambda r: r[0] == "ResourceNotFoundException",
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert code == "ResourceNotFoundException", (
        f"expected GetStreamGroup on a deleted group to raise ResourceNotFoundException, got {code!r}"
    )
    expected = f"Resource '{arn}' does not exist"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # The dead identifier is not just unreadable but unusable: a further mutation
    # against it must also fail with the same not-found code, not a silent no-op.
    second_delete_code, second_delete_message = _error_code(
        lambda: gls.delete_stream_group(Identifier=arn)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        "expected a second DeleteStreamGroup on an already-deleted group to raise "
        f"ResourceNotFoundException, got {second_delete_code!r}"
    )
    assert _without_internal_id(second_delete_message) == expected, (
        f"expected {expected!r}, got {second_delete_message!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable

def _delete_stream_group_when_settled(gls, arn, timeout_s=1800.0, interval_s=15.0):
    """DeleteStreamGroup refuses a group that is still ACTIVATING, so retry until it is
    accepted, then wait until the group is gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gls.delete_stream_group(Identifier=arn)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while True:
        try:
            gls.get_stream_group(Identifier=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream group {arn} still present after {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
