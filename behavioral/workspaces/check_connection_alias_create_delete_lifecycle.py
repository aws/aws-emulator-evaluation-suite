"""connection-alias-create-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "connection-alias-create-delete-lifecycle"
GROUP = "state"
SERVICES = ["workspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnectionAlias transitions CREATING->CREATED; DeleteConnectionAlias removes it
    from DescribeConnectionAliases."""
    ws = ctx.client("workspaces")
    connection_string = f"{ctx.unique_name('sim2real-wsca')}.example.com".lower()

    alias_id = ws.create_connection_alias(
        ConnectionString=connection_string,
        Tags=[{"Key": "env", "Value": "sim2real"}],
    )["AliasId"]
    ctx.on_cleanup(lambda: _safe_delete_alias(ctx, alias_id))

    state = _poll_until(
        lambda: _describe_alias(ctx, alias_id)["State"],
        lambda s: s == "CREATED",
        timeout_s=120.0,
    )
    assert state == "CREATED", f"expected CREATED, got {state!r}"

    alias = _describe_alias(ctx, alias_id)
    assert alias["ConnectionString"] == connection_string, (
        f"expected {connection_string!r}, got {alias['ConnectionString']!r}"
    )

    ws.delete_connection_alias(AliasId=alias_id)
    gone = _poll_until(
        lambda: len(ws.describe_connection_aliases(AliasIds=[alias_id])["ConnectionAliases"]),
        lambda n: n == 0,
        timeout_s=60.0,
    )
    assert gone == 0, "connection alias still present after delete"

    err = _client_error(lambda: ws.delete_connection_alias(AliasId=alias_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted alias, got {err['Code']!r}"
    )
    expected = (
        "The connection alias couldn\u2019t be found. Make sure that you have the correct "
        "connection alias, and then try again."
    )
    assert err.get("Message") == expected, f"unexpected message: {err.get('Message')!r}"


def _describe_alias(ctx, alias_id: str) -> dict:
    ws = ctx.client("workspaces")
    aliases = ws.describe_connection_aliases(AliasIds=[alias_id])["ConnectionAliases"]
    assert len(aliases) == 1, f"expected exactly one alias, got {aliases}"
    return aliases[0]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded with: {result!r}")


def _safe_delete_alias(ctx, alias_id: str) -> None:
    from botocore.exceptions import ClientError

    ws = ctx.client("workspaces")
    try:
        ws.delete_connection_alias(AliasId=alias_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
