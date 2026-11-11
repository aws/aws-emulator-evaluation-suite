"""remove-last-stream-group-location-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-last-stream-group-location-rejected"
GROUP = "overly-permissive"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveStreamGroupLocations rejects removing the ONLY remaining location in a stream
    group with ValidationException and the location stays in place, while removing a location
    from a group that has TWO locations succeeds (positive control) in the same run."""
    gls = ctx.client("gameliftstreams")
    primary_location = ctx.region
    # region-pinned: a second GameLift Streams location distinct from ctx.region is required to
    # build the two-location positive control; these two are GameLift Streams-supported locations.
    secondary_location = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"

    try:
        group = gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen4n_high",
            LocationConfigurations=[{"LocationName": primary_location, "MaximumCapacity": 2}],
            Tags={"sim2real-env": "test"},
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

    with_primary = _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda g: any(
            loc["LocationName"] == primary_location and loc["Status"] in ("ACTIVE", "ERROR")
            for loc in g["LocationStates"]
        ),
        timeout_s=600.0,
        interval_s=15.0,
    )
    primary_status = _location_status(with_primary, primary_location)
    assert primary_status == "ACTIVE", f"expected primary location ACTIVE, got {primary_status!r}"

    gls.add_stream_group_locations(
        Identifier=arn,
        LocationConfigurations=[{"LocationName": secondary_location, "MaximumCapacity": 2}],
    )
    with_both = _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda g: len(g["LocationStates"]) == 2
        and all(loc["Status"] in ("ACTIVE", "ERROR") for loc in g["LocationStates"]),
        timeout_s=600.0,
        interval_s=15.0,
    )
    secondary_status = _location_status(with_both, secondary_location)
    assert secondary_status == "ACTIVE", (
        f"expected secondary location ACTIVE, got {secondary_status!r}"
    )

    # positive control: removing one of TWO locations succeeds. Real AWS drains a removed
    # location's capacity through a REMOVING status before dropping it from LocationStates
    # entirely (the model has no terminal "removed" status). That drain can take longer than
    # 300s, so the poll window matches add/create.
    gls.remove_stream_group_locations(Identifier=arn, Locations=[secondary_location])
    with_one = _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda g: len(g["LocationStates"]) == 1,
        timeout_s=900.0,
        interval_s=15.0,
    )
    remaining_name = with_one["LocationStates"][0]["LocationName"]
    assert remaining_name == primary_location, (
        f"expected only {primary_location!r} to remain, got {remaining_name!r}"
    )

    # negative: removing the ONLY remaining location is rejected
    code, message = _error_code(
        lambda: gls.remove_stream_group_locations(Identifier=arn, Locations=[primary_location])
    )
    assert code == "ValidationException", (
        f"expected ValidationException removing the last location, got {code!r}"
    )
    expected = (
        f"The primary service location '{primary_location}' cannot be removed from stream "
        f"group '{arn}', set capacity to zero instead"
    )
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: the last location is still present
    reread = gls.get_stream_group(Identifier=arn)
    reread_count = len(reread["LocationStates"])
    assert reread_count == 1, f"expected 1 location to remain, got {reread_count}"
    reread_name = reread["LocationStates"][0]["LocationName"]
    assert reread_name == primary_location, (
        f"expected remaining location {primary_location!r}, got {reread_name!r}"
    )


def _location_status(group, location_name):
    return next(
        loc["Status"] for loc in group["LocationStates"] if loc["LocationName"] == location_name
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
