"""list-connections-filters-are-mutually-exclusive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-connections-filters-are-mutually-exclusive"
GROUP = 'connection'
SERVICES = ['events']

_COMBINED_FILTER_REFUSAL = (
    "Failed to list the connection(s). Request failed because only one filter is supported per "
    "request, either ConnectionState or NamePrefix."
)

def _error(fn):
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _cleanup_connection(ev, name):
    """Best-effort DeleteConnection (asynchronous; the connection disappears later)."""
    try:
        ev.delete_connection(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnections accepts one filter per request: NamePrefix and ConnectionState each work
    alone, but combining them is rejected with ValidationException."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-conn-")
    ev.create_connection(
        Name=name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "secret-value"}
        },
    )
    ctx.on_cleanup(lambda n=name: _cleanup_connection(ev, n))
    # The connection reaches AUTHORIZED asynchronously.
    _deadline = time.monotonic() + 60
    while time.monotonic() < _deadline:
        d = ev.describe_connection(Name=name)
        if d["ConnectionState"] in ("AUTHORIZED", "CREATE_FAILED"):
            break
        time.sleep(1)

    by_prefix = ev.list_connections(NamePrefix=name)["Connections"]
    assert {c["Name"] for c in by_prefix} == {name}, f"NamePrefix filter broken: {by_prefix}"
    assert by_prefix[0]["ConnectionState"] == "AUTHORIZED", f"unexpected state: {by_prefix}"

    err = _error(
        lambda: ev.list_connections(NamePrefix=name, ConnectionState="AUTHORIZED")
    )
    assert err == ("ValidationException", _COMBINED_FILTER_REFUSAL), (
        f"expected ValidationException when combining ListConnections filters, got {err!r}"
    )

    deauthorized = ev.list_connections(ConnectionState="DEAUTHORIZED")["Connections"]
    assert name not in {c["Name"] for c in deauthorized}, (
        f"AUTHORIZED connection must not match DEAUTHORIZED filter: {deauthorized}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
