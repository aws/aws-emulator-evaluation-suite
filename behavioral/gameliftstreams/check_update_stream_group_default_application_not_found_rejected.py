"""update-stream-group-default-application-not-found-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stream-group-default-application-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStreamGroup on an ACTIVE group with a DefaultApplicationIdentifier that does not exist fails with
    ValidationException and its message and leaves DefaultApplication unset, while updating Description
    succeeds.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    gls = ctx.client("gameliftstreams")
    try:
        group = gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen4n_high",
            LocationConfigurations=[{"LocationName": ctx.region, "MaximumCapacity": 2}],
            Tags={"sim2real": CHECK},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _delete_stream_group_when_settled(gls, arn, teardown_deadline))
    assert "DefaultApplication" not in group or group.get("DefaultApplication") is None, (
        f"expected a freshly created stream group to have no DefaultApplication, got "
        f"{group.get('DefaultApplication')!r}"
    )

    active = _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda g: g["Status"] not in ("ACTIVATING", "UPDATING_LOCATIONS"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert active["Status"] == "ACTIVE", (
        f"expected the stream group to reach ACTIVE, got {active['Status']} "
        f"({active.get('StatusReason')})"
    )

    bad_app_id = ctx.unique_name("a-")
    code, message = _error_code(
        lambda: gls.update_stream_group(
            Identifier=arn, DefaultApplicationIdentifier=bad_app_id
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a DefaultApplicationIdentifier that does not exist "
        f"({bad_app_id!r}); real AWS does not resolve this as a ResourceNotFoundException "
        f"lookup, got {code!r}"
    )
    bad_app_arn = arn.split(":streamgroup/")[0] + f":application/{bad_app_id}"
    expected = (
        f"Application '{bad_app_arn}' cannot be set as default because it is not currently "
        "associated with the stream group"
    )
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: no default application was set on the group
    reread = gls.get_stream_group(Identifier=arn)
    assert not reread.get("DefaultApplication"), (
        f"rejected UpdateStreamGroup must not set DefaultApplication, got "
        f"{reread.get('DefaultApplication')!r}"
    )

    # positive control: a legitimate update (Description) succeeds
    new_description = ctx.unique_name("sim2real-gls-sg-updated-")
    updated = gls.update_stream_group(Identifier=arn, Description=new_description)
    assert updated["Description"] == new_description, (
        f"expected UpdateStreamGroup response Description {new_description!r}, got "
        f"{updated['Description']!r}"
    )
    reread2 = gls.get_stream_group(Identifier=arn)
    assert reread2["Description"] == new_description, (
        f"expected GetStreamGroup Description {new_description!r} after the legitimate update, "
        f"got {reread2['Description']!r}"
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


# The suite's 900 s teardown budget: one deadline shared by every teardown of a run.
_TEARDOWN_S = 900.0


def _teardown_deadline(teardown_deadline):
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S - 120.0)


def _delete_stream_group_when_settled(gls, arn, teardown_deadline, interval_s=2.0):
    """DeleteStreamGroup refuses a group that is still ACTIVATING, so retry until it is
    accepted, then wait until the group is gone, to the shared teardown deadline."""
    from botocore.exceptions import ClientError

    deadline = _teardown_deadline(teardown_deadline)
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
            raise AssertionError(f"stream group {arn} still present at the teardown deadline")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
