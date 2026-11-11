"""oauth-connection-with-unreachable-endpoint-deauthorizes-and-its-destination-is-inactive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "oauth-connection-with-unreachable-endpoint-deauthorizes-and-its-destination-is-inactive"
GROUP = "connection"
SERVICES = ["events"]

_SETTLE_TIMEOUT_S = 180.0
# RFC 2606 reserves .invalid: it never resolves, so the token request can never be answered.
_UNREACHABLE_TOKEN_URL = "https://sim2real.invalid/oauth/token"
_HOOK_URL = "https://sim2real.invalid/hook"


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An OAuth connection whose token endpoint is unreachable goes DEAUTHORIZED and its API
    destination INACTIVE, while a BASIC connection needs no token exchange and its destination is
    ACTIVE. The OAuth outcome comes from EventBridge's own token request, after CreateConnection.
    """
    events = ctx.client("events")

    oauth_name = ctx.unique_name("sim2real-behav-conn-")
    oauth = events.create_connection(
        Name=oauth_name,
        AuthorizationType="OAUTH_CLIENT_CREDENTIALS",
        AuthParameters={"OAuthParameters": {
            "ClientParameters": {"ClientID": "sim2real-client", "ClientSecret": "sim2real-secret"},
            "AuthorizationEndpoint": _UNREACHABLE_TOKEN_URL,
            "HttpMethod": "POST",
        }},
    )
    ctx.on_cleanup(lambda: events.delete_connection(Name=oauth_name))
    assert oauth["ConnectionState"] == "AUTHORIZING", (
        f"an OAuth connection starts by AUTHORIZING (it must fetch a token), got {oauth['ConnectionState']!r}"
    )

    basic_name = ctx.unique_name("sim2real-behav-conn-")
    basic = events.create_connection(
        Name=basic_name,
        AuthorizationType="BASIC",
        AuthParameters={"BasicAuthParameters": {"Username": "sim2real", "Password": "sim2real-pw"}},
    )
    ctx.on_cleanup(lambda: events.delete_connection(Name=basic_name))

    basic_state = _poll(lambda: events.describe_connection(Name=basic_name),
                        lambda d: d["ConnectionState"] not in ("CREATING", "AUTHORIZING"), "BASIC connection settles")
    assert basic_state["ConnectionState"] == "AUTHORIZED", (
        f"positive control: a BASIC connection must be AUTHORIZED, got {basic_state['ConnectionState']!r} "
        f"({basic_state.get('StateReason')!r})"
    )

    oauth_state = _poll(lambda: events.describe_connection(Name=oauth_name),
                        lambda d: d["ConnectionState"] not in ("CREATING", "AUTHORIZING"), "OAuth connection settles")
    assert oauth_state["ConnectionState"] == "DEAUTHORIZED", (
        f"an OAuth connection whose token endpoint is unreachable must end DEAUTHORIZED, got "
        f"{oauth_state['ConnectionState']!r} ({oauth_state.get('StateReason')!r})"
    )
    assert oauth_state.get("StateReason") == "Could not connect to the specified endpoint.", (
        f"StateReason was {oauth_state.get('StateReason')!r}"
    )

    good_dest = ctx.unique_name("sim2real-behav-dest-")
    good = events.create_api_destination(
        Name=good_dest, ConnectionArn=basic["ConnectionArn"], InvocationEndpoint=_HOOK_URL, HttpMethod="POST",
    )
    ctx.on_cleanup(lambda: events.delete_api_destination(Name=good_dest))
    bad_dest = ctx.unique_name("sim2real-behav-dest-")
    bad = events.create_api_destination(
        Name=bad_dest, ConnectionArn=oauth["ConnectionArn"], InvocationEndpoint=_HOOK_URL, HttpMethod="POST",
    )
    ctx.on_cleanup(lambda: events.delete_api_destination(Name=bad_dest))

    good_state = _poll(lambda: events.describe_api_destination(Name=good_dest)["ApiDestinationState"],
                       lambda s: s is not None, "destination on BASIC reports a state")
    assert good_state == "ACTIVE", (
        f"an API destination on an AUTHORIZED connection must be ACTIVE, got {good_state!r} "
        f"(create answered {good['ApiDestinationState']!r})"
    )
    bad_state = events.describe_api_destination(Name=bad_dest)["ApiDestinationState"]
    assert bad_state == "INACTIVE", (
        f"an API destination on a DEAUTHORIZED connection must be INACTIVE, got {bad_state!r} "
        f"(create answered {bad['ApiDestinationState']!r})"
    )


def _poll(read, done, what: str):
    deadline = time.monotonic() + _SETTLE_TIMEOUT_S
    value = None
    while time.monotonic() < deadline:
        value = read()
        if done(value):
            return value
        time.sleep(3)
    raise AssertionError(f"timed out after {_SETTLE_TIMEOUT_S}s waiting until {what}; last read {value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
