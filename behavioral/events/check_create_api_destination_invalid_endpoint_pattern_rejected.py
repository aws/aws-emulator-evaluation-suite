"""create-api-destination-invalid-endpoint-pattern-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-destination-invalid-endpoint-pattern-rejected"
GROUP = "api-destination"
SERVICES = ["events"]

#: A character InvocationEndpoint's documented pattern never admits.
_INVALID_ENDPOINT = "https://sim2real.invalid/a b"

_PATTERN = r"^((%[0-9A-Fa-f]{2}|[-()_.!~*';/?:@\x26=+$,A-Za-z0-9])+)([).!';/?:,])?$"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) if it raised a ClientError. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _wait_active(events, name: str, timeout_s: float) -> dict:
    """Poll DescribeApiDestination until ApiDestinationState settles ACTIVE; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    desc = events.describe_api_destination(Name=name)
    while desc["ApiDestinationState"] != "ACTIVE":
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"api destination {name!r} did not settle ACTIVE within {timeout_s:.0f}s; "
                f"last state {desc['ApiDestinationState']!r}"
            )
        time.sleep(2)
        desc = events.describe_api_destination(Name=name)
    return desc


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiDestination refuses an InvocationEndpoint carrying a character its documented
    pattern excludes, with ValidationException naming the value and the pattern, while a bare
    non-URL string that satisfies the pattern is still accepted and stored verbatim.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_CreateApiDestination.html
    """
    events = ctx.client("events")

    conn_name = ctx.unique_name("sim2real-behav-conn-")
    conn_arn = events.create_connection(
        Name=conn_name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "sim2real-secret"}
        },
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: events.delete_connection(Name=conn_name))

    bad_name = ctx.unique_name("sim2real-behav-dest-")
    code, message = _error(
        lambda: events.create_api_destination(
            Name=bad_name,
            ConnectionArn=conn_arn,
            InvocationEndpoint=_INVALID_ENDPOINT,
            HttpMethod="POST",
        )
    )
    expected = (
        "ValidationException",
        f"1 validation error detected: Value '{_INVALID_ENDPOINT}' at 'invocationEndpoint' "
        f"failed to satisfy constraint: Member must satisfy regular expression pattern: {_PATTERN}",
    )
    assert (code, message) == expected, (
        f"expected the malformed endpoint to be refused with {expected!r}, got {(code, message)!r}"
    )

    missing = _error(lambda: events.describe_api_destination(Name=bad_name))
    assert missing[0] == "ResourceNotFoundException", (
        f"a rejected CreateApiDestination must not leave a destination behind, got {missing!r}"
    )

    # Positive control: a non-URL string that still satisfies the pattern is accepted and stored
    # verbatim, so the rejection above is about the pattern, not about "not a URL".
    good_name = ctx.unique_name("sim2real-behav-dest-")
    good_endpoint = "sim2real-non-url-endpoint"
    events.create_api_destination(
        Name=good_name,
        ConnectionArn=conn_arn,
        InvocationEndpoint=good_endpoint,
        HttpMethod="POST",
    )
    ctx.on_cleanup(lambda: events.delete_api_destination(Name=good_name))

    desc = _wait_active(events, good_name, _budget_s(ctx, 60.0))
    assert desc["ApiDestinationState"] == "ACTIVE", (
        f"the api destination must settle ACTIVE, got {desc['ApiDestinationState']!r}"
    )
    assert desc["InvocationEndpoint"] == good_endpoint, (
        f"expected the endpoint to be stored verbatim, got {desc['InvocationEndpoint']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
