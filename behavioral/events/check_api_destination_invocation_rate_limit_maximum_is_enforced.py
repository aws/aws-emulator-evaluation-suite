"""api-destination-invocation-rate-limit-maximum-is-enforced."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# The Smithy model only has `@range(min: 1)`; the maximum is a service-side rule, so it is
# measured by bisection rather than pinned. The lower bound (0) is not probed: botocore enforces
# `min: 1` client-side, so that request never reaches the service.

CHECK = "api-destination-invocation-rate-limit-maximum-is-enforced"
GROUP = "api-destination"
SERVICES = ["events"]

_CEILING = 1024  # bisection ceiling: comfortably above the documented 300
_FLOOR = 10  # sanity floor: the documented range is 1..300, so a maximum below 10 is a target bug
_AUTHORIZED_TIMEOUT_S = 120.0
_ACTIVE_TIMEOUT_S = 90.0
_CONFLICT_RETRY_S = 20.0
# RFC 5737 TEST-NET-1: reserved for documentation and routed nowhere. Nothing here invokes the
# destination; the endpoint exists only because CreateApiDestination requires one.
_ENDPOINT = "https://192.0.2.1/sim2real-hook"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """InvocationRateLimitPerSecond has a finite maximum, enforced identically by Create and Update
    with LimitExceededException; the maximum is stored verbatim, a refused write changes nothing,
    and an invalid HttpMethod is refused without disturbing the destination."""
    events = ctx.client("events")

    conn_name = ctx.unique_name("sim2real-behav-conn-")
    conn = events.create_connection(
        Name=conn_name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "sim2real-not-a-secret"}
        },
    )
    ctx.on_cleanup(lambda n=conn_name: _delete_quietly(ctx, "connection", n))
    authorized = _poll_until(
        lambda: events.describe_connection(Name=conn_name),
        lambda d: d["ConnectionState"] in ("AUTHORIZED", "CREATE_FAILED"),
        timeout_s=_AUTHORIZED_TIMEOUT_S,
        interval_s=2.0,
        description=f"connection {conn_name} leaves CREATING",
    )
    assert authorized["ConnectionState"] == "AUTHORIZED", (
        f"an API_KEY connection must reach AUTHORIZED before a destination can use it, got "
        f"{authorized['ConnectionState']!r} StateReason={authorized.get('StateReason')!r}"
    )

    # Positive control: the smallest legal value is accepted and echoed exactly.
    dest = ctx.unique_name("sim2real-behav-apidest-")
    events.create_api_destination(
        Name=dest,
        ConnectionArn=conn["ConnectionArn"],
        InvocationEndpoint=_ENDPOINT,
        HttpMethod="POST",
        InvocationRateLimitPerSecond=1,
    )
    ctx.on_cleanup(lambda n=dest: _delete_quietly(ctx, "api_destination", n))
    _wait_active(events, dest)
    assert _stored_rate(events, dest) == 1, (
        f"positive control failed: InvocationRateLimitPerSecond=1 must be stored verbatim, "
        f"DescribeApiDestination reports {_stored_rate(events, dest)!r}"
    )

    # The ceiling must be refused first so the bisection interval is bracketed on both sides.
    over_ceiling = _update_rate_limit(events, dest, _CEILING)
    assert over_ceiling is not None, (
        f"InvocationRateLimitPerSecond={_CEILING} was ACCEPTED — real EventBridge documents a "
        f"maximum of 300 events per second, so a target with no maximum at all is what this "
        f"measures"
    )
    update_max = _max_accepted_rate(events, dest)
    assert _FLOOR <= update_max < _CEILING, (
        f"the measured maximum InvocationRateLimitPerSecond must be finite and no smaller than "
        f"{_FLOOR} (the documented range is 1..300); measured {update_max}"
    )
    expected_ceiling = _rate_refusal("update", _CEILING, dest, update_max)
    assert over_ceiling == expected_ceiling, (
        f"UpdateApiDestination rate={_CEILING} must be refused with {expected_ceiling}, "
        f"got {over_ceiling}"
    )

    # The boundary value is stored verbatim, not clamped.
    conflict = _update_rate_limit(events, dest, update_max)
    assert conflict is None, (
        f"re-applying the measured maximum {update_max} must succeed, got {conflict}"
    )
    _wait_active(events, dest)
    assert _stored_rate(events, dest) == update_max, (
        f"the maximum accepted rate limit must round-trip verbatim: set {update_max}, "
        f"DescribeApiDestination reports {_stored_rate(events, dest)!r} — a silent clamp changes "
        f"delivery behaviour, which no other read observes"
    )

    # One over the maximum is refused and leaves the stored value untouched.
    refused_update = _update_rate_limit(events, dest, update_max + 1)
    assert refused_update is not None, (
        f"UpdateApiDestination accepted {update_max + 1} immediately after refusing it during the "
        f"bisection — the maximum is not applied consistently"
    )
    expected_update_refusal = _rate_refusal("update", update_max + 1, dest, update_max)
    assert refused_update == expected_update_refusal, (
        f"UpdateApiDestination rate={update_max + 1} must be refused with "
        f"{expected_update_refusal}, got {refused_update}"
    )
    assert _stored_rate(events, dest) == update_max, (
        f"the refused update must not have written: expected the stored rate limit to still be "
        f"{update_max}, DescribeApiDestination reports {_stored_rate(events, dest)!r}"
    )

    # The create path must enforce the same maximum, in both directions.
    at_max_name = ctx.unique_name("sim2real-behav-apidest-")
    events.create_api_destination(
        Name=at_max_name,
        ConnectionArn=conn["ConnectionArn"],
        InvocationEndpoint=_ENDPOINT,
        HttpMethod="POST",
        InvocationRateLimitPerSecond=update_max,
    )
    ctx.on_cleanup(lambda n=at_max_name: _delete_quietly(ctx, "api_destination", n))
    _wait_active(events, at_max_name)
    assert _stored_rate(events, at_max_name) == update_max, (
        f"CreateApiDestination must accept and store the same maximum the update path accepts: set "
        f"{update_max}, got {_stored_rate(events, at_max_name)!r}"
    )

    over_max_name = ctx.unique_name("sim2real-behav-apidest-")
    create_refusal = _error(
        lambda: events.create_api_destination(
            Name=over_max_name,
            ConnectionArn=conn["ConnectionArn"],
            InvocationEndpoint=_ENDPOINT,
            HttpMethod="POST",
            InvocationRateLimitPerSecond=update_max + 1,
        )
    )
    expected_create_refusal = _rate_refusal("create", update_max + 1, over_max_name, update_max)
    assert create_refusal == expected_create_refusal, (
        f"CreateApiDestination must refuse InvocationRateLimitPerSecond={update_max + 1} exactly as "
        f"UpdateApiDestination does: expected {expected_create_refusal}, got {create_refusal}"
    )
    absent = _error(lambda: events.describe_api_destination(Name=over_max_name))
    expected_absent = (
        "ResourceNotFoundException",
        f"Failed to describe the api-destination(s). An api-destination '{over_max_name}' "
        "does not exist.",
    )
    assert absent == expected_absent, (
        f"the refused CreateApiDestination must not have created anything: "
        f"DescribeApiDestination({over_max_name}) returned {absent!r}, expected {expected_absent!r}"
    )
    assert (
        events.list_api_destinations(NamePrefix=over_max_name).get("ApiDestinations") == []
    ), (
        f"the refused CreateApiDestination must leave nothing in "
        f"ListApiDestinations(NamePrefix={over_max_name!r}), got "
        f"{events.list_api_destinations(NamePrefix=over_max_name).get('ApiDestinations')!r}"
    )

    # botocore does not validate Smithy enums, so HttpMethod="BOGUS" reaches the service.
    bad_method = _error(lambda: events.update_api_destination(Name=dest, HttpMethod="BOGUS"))
    assert bad_method[0] is not None, (
        "UpdateApiDestination ACCEPTED HttpMethod='BOGUS' — botocore does not validate Smithy enums, "
        "so this request really did reach the service and the service must refuse it"
    )
    described = events.describe_api_destination(Name=dest)
    assert described["HttpMethod"] == "POST", (
        f"the refused HttpMethod update must not have written: expected POST, got "
        f"{described['HttpMethod']!r}"
    )
    assert described["InvocationRateLimitPerSecond"] == update_max, (
        f"the refused HttpMethod update must not have disturbed the rate limit either: expected "
        f"{update_max}, got {described['InvocationRateLimitPerSecond']!r}"
    )


# ===== self-contained helpers =====
def _error(fn) -> tuple[str, str]:
    """(code, message) for a call expected to fail; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _rate_refusal(verb: str, rate: int, name: str, maximum: int) -> tuple[str, str]:
    """The refusal EventBridge returns for a rate limit above the maximum on create or update."""
    return (
        "LimitExceededException",
        f"Failed to {verb} the api-destination(s). Invalid Invocation Rate Limit: Rate specified "
        f"'{rate}' for '{name}' exceeds maximum allowed of '{maximum}'.",
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds; RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_active(events, name: str) -> None:
    state = _poll_until(
        lambda: events.describe_api_destination(Name=name),
        lambda d: d["ApiDestinationState"] in ("ACTIVE", "INACTIVE"),
        timeout_s=_ACTIVE_TIMEOUT_S,
        interval_s=2.0,
        description=f"api destination {name} settles",
    )
    assert state["ApiDestinationState"] == "ACTIVE", (
        f"api destination {name} must reach ACTIVE, got {state['ApiDestinationState']!r}"
    )


def _stored_rate(events, name: str) -> int:
    """The rate limit as read back by DescribeApiDestination; an absent field fails loudly."""
    return events.describe_api_destination(Name=name)["InvocationRateLimitPerSecond"]


def _update_rate_limit(events, name: str, value: int):
    """None if the update was accepted, else (code, message). ConcurrentModificationException from
    back-to-back bisection updates is retried under a deadline, not counted as a rejection."""
    deadline = time.monotonic() + _CONFLICT_RETRY_S
    while True:
        try:
            events.update_api_destination(Name=name, InvocationRateLimitPerSecond=value)
            return None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "ConcurrentModificationException":
                return code, exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"UpdateApiDestination({name}, rate={value}) kept returning "
                f"ConcurrentModificationException for {_CONFLICT_RETRY_S}s, so the probe could not "
                f"be classified as accepted or refused"
            )
        time.sleep(1.0)


def _max_accepted_rate(events, name: str) -> int:
    """Bisect [1, _CEILING] for the greatest rate limit UpdateApiDestination accepts;
    the caller has already seen 1 accepted and _CEILING refused."""
    low, high = 1, _CEILING  # accepted, refused
    while high - low > 1:
        mid = (low + high) // 2
        if _update_rate_limit(events, name, mid) is None:
            low = mid
        else:
            high = mid
    return low


def _delete_quietly(ctx, kind: str, name: str) -> None:
    """Delete a connection or API destination; any error other than not-found raises."""
    events = ctx.client("events")
    call = (
        (lambda: events.delete_connection(Name=name))
        if kind == "connection"
        else (lambda: events.delete_api_destination(Name=name))
    )
    try:
        call()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code != "ResourceNotFoundException":
            raise RuntimeError(
                f"could not delete {kind} {name}: {code} {exc.response['Error'].get('Message')}"
            ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
