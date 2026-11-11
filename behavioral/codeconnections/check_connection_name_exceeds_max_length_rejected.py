"""connection-name-exceeds-max-length-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-name-exceeds-max-length-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeconnections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection rejects a ConnectionName longer than the documented 32-character
    maximum with ValidationException, and no connection is created; a name at the limit
    still succeeds (positive control)."""
    cc = ctx.client("codeconnections")
    too_long_name = ctx.unique_name("sim2real-conn-") + ("x" * 40)
    assert len(too_long_name) > 32, (
        f"test setup: too_long_name is {len(too_long_name)} chars, need >32 to exercise the limit"
    )

    def _cleanup_if_leaked(result):
        arn = result.get("ConnectionArn")
        if arn:
            ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))

    code, message = _error_code(
        lambda: cc.create_connection(ConnectionName=too_long_name, ProviderType="GitHub"),
        on_unexpected_success=_cleanup_if_leaked,
    )
    assert code == "ValidationException", (
        f"expected ValidationException creating a {len(too_long_name)}-char ConnectionName "
        f"(documented limit is 32), got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'connectionName' failed to satisfy constraint: "
        "Member must have length less than or equal to 32"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no connection with this (truncated-searchable) prefix exists
    prefix = too_long_name[:32]
    names = {c["ConnectionName"] for c in _iter_connections(cc)}
    assert not any(n.startswith(prefix[:20]) for n in names), (
        f"found a connection whose name starts with the rejected prefix {prefix[:20]!r}; "
        "the rejected CreateConnection should not have created anything"
    )

    # positive control: a name within the limit succeeds
    ok_name = ctx.unique_name("sim2real-conn-")[:32]
    arn = cc.create_connection(ConnectionName=ok_name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))
    got_name = cc.get_connection(ConnectionArn=arn)["Connection"]["ConnectionName"]
    assert got_name == ok_name, (
        f"positive control: GetConnection returned ConnectionName={got_name!r}, expected {ok_name!r}"
    )


def _error_code(fn, on_unexpected_success=None):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _iter_connections(cc):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_connections(**kwargs)
        yield from resp.get("Connections", [])
        token = resp.get("NextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
