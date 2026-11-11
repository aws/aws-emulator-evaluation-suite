"""connection-malformed-host-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-malformed-host-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeconnections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection rejects a HostArn that does not match the required ARN pattern
    (arn:aws...:host/...) with ValidationException, and no connection is created; the
    same call without a HostArn still succeeds (positive control)."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]

    def _cleanup_if_leaked(result):
        arn = result.get("ConnectionArn")
        if arn:
            ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))

    code, message = _error_code(
        lambda: cc.create_connection(ConnectionName=name, HostArn="not-an-arn"),
        on_unexpected_success=_cleanup_if_leaked,
    )
    assert code == "ValidationException", (
        f"expected ValidationException creating a connection with malformed HostArn "
        f"'not-an-arn', got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'hostArn' failed to satisfy constraint: Member must "
        r"satisfy regular expression pattern: arn:aws(-[\w]+)*:(codestar-connections|codeconnections):.+:"
        r"[0-9]{12}:host\/.+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no connection with this name was created
    names = {c["ConnectionName"] for c in _iter_connections(cc)}
    assert name not in names, (
        f"found a connection named {name!r}; the rejected CreateConnection "
        "should not have created anything"
    )

    # positive control: omitting HostArn entirely succeeds (ProviderType supplied instead)
    arn = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))
    got = cc.get_connection(ConnectionArn=arn)["Connection"]
    assert "HostArn" not in got, (
        f"positive control: GetConnection returned HostArn={got.get('HostArn')!r} "
        "for a connection created without one"
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
