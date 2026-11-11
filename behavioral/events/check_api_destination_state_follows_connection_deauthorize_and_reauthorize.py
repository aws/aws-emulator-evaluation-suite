"""api-destination-state-follows-connection-deauthorize-and-reauthorize."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-destination-state-follows-connection-deauthorize-and-reauthorize"
GROUP = "connection"
SERVICES = ["events"]

_SETTLE_TIMEOUT_S = 180.0
_HOOK_URL = "https://sim2real.invalid/hook"


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An API destination's state follows its BASIC connection: ACTIVE while AUTHORIZED, INACTIVE
    after DeauthorizeConnection, ACTIVE again after re-authorizing; an UpdateConnection naming auth
    parameters without AuthorizationType is refused and leaves the connection deauthorized."""
    events = ctx.client("events")

    conn = ctx.unique_name("sim2real-behav-conn-")
    conn_arn = events.create_connection(
        Name=conn,
        AuthorizationType="BASIC",
        AuthParameters={"BasicAuthParameters": {"Username": "sim2real", "Password": "sim2real-pw-1"}},
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: events.delete_connection(Name=conn))
    _settle_connection(events, conn, "AUTHORIZED")

    dest = ctx.unique_name("sim2real-behav-dest-")
    dest_arn = events.create_api_destination(
        Name=dest, ConnectionArn=conn_arn, InvocationEndpoint=_HOOK_URL, HttpMethod="POST",
    )["ApiDestinationArn"]
    ctx.on_cleanup(lambda: events.delete_api_destination(Name=dest))
    _settle_destination(events, dest, "ACTIVE")

    events.deauthorize_connection(Name=conn)
    _settle_connection(events, conn, "DEAUTHORIZED")
    _settle_destination(events, dest, "INACTIVE")

    code, message = _error(lambda: events.update_connection(
        Name=conn, AuthParameters={"BasicAuthParameters": {"Username": "sim2real", "Password": "sim2real-pw-2"}},
    ))
    assert (code, message) == (
        "ValidationException",
        "Failed to update the connection(s). At least one of the following is required: Description, "
        "KmsKeyIdentifier, AuthorizationType with BasicAuthParameters, ApiKeyAuthParameters, or OAuthParameters.",
    ), f"auth parameters without AuthorizationType must be refused, got {code!r} {message!r}"
    assert events.describe_connection(Name=conn)["ConnectionState"] == "DEAUTHORIZED", (
        "the refused UpdateConnection must leave the connection DEAUTHORIZED"
    )

    events.update_connection(
        Name=conn,
        AuthorizationType="BASIC",
        AuthParameters={"BasicAuthParameters": {"Username": "sim2real", "Password": "sim2real-pw-2"}},
    )
    _settle_connection(events, conn, "AUTHORIZED")
    _settle_destination(events, dest, "ACTIVE")

    described = events.describe_api_destination(Name=dest)
    assert described["ApiDestinationArn"] == dest_arn and described["ConnectionArn"] == conn_arn, (
        "re-authorizing must keep the same API destination bound to the same connection"
    )


def _settle_connection(events, name: str, want: str) -> None:
    transient = ("CREATING", "UPDATING", "AUTHORIZING", "DEAUTHORIZING")
    got = _poll(lambda: events.describe_connection(Name=name),
                lambda d: d["ConnectionState"] not in transient, f"connection leaves {transient}")
    assert got["ConnectionState"] == want, (
        f"connection settled in {got['ConnectionState']!r} ({got.get('StateReason')!r}), expected {want!r}"
    )


def _settle_destination(events, name: str, want: str) -> None:
    got = _poll(lambda: events.describe_api_destination(Name=name)["ApiDestinationState"],
                lambda s: s == want, f"API destination becomes {want}")
    assert got == want, f"API destination state {got!r}, expected {want!r}"


def _poll(read, done, what: str):
    deadline = time.monotonic() + _SETTLE_TIMEOUT_S
    value = None
    while time.monotonic() < deadline:
        value = read()
        if done(value):
            return value
        time.sleep(3)
    raise AssertionError(f"timed out after {_SETTLE_TIMEOUT_S}s waiting until {what}; last read {value!r}")


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
