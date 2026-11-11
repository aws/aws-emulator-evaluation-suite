"""start-server-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-server-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartServer, StopServer and DescribeServer fail with ResourceNotFoundException "Unknown
    server" on a well-formed nonexistent ServerId and on the id of a server the check created and
    deleted."""
    transfer = ctx.client("transfer")

    fake_server_id = "s-00000000000000000"

    code, message = _err(lambda: transfer.start_server(ServerId=fake_server_id))
    assert code == "ResourceNotFoundException", (
        f"StartServer on a well-formed but never-created ServerId {fake_server_id} "
        f"must be rejected with ResourceNotFoundException, got {code!r}"
    )
    assert message == "Unknown server", f"unexpected ResourceNotFoundException message {message!r}"

    code, message = _err(lambda: transfer.stop_server(ServerId=fake_server_id))
    assert code == "ResourceNotFoundException", (
        f"StopServer on a well-formed but never-created ServerId {fake_server_id} "
        f"must be rejected with ResourceNotFoundException, got {code!r}"
    )
    assert message == "Unknown server", f"unexpected ResourceNotFoundException message {message!r}"

    code, message = _err(lambda: transfer.describe_server(ServerId=fake_server_id))
    assert code == "ResourceNotFoundException", (
        f"DescribeServer on a well-formed but never-created ServerId {fake_server_id} "
        f"must be rejected with ResourceNotFoundException, got {code!r}"
    )
    assert message == "Unknown server", f"unexpected ResourceNotFoundException message {message!r}"

    # positive control: create a real server, describe it successfully, delete it,
    # then confirm the SAME operations 404 against that now-deleted (but once real)
    # ServerId -- proving the negative path isn't just "malformed ID" special-casing.
    server_id = transfer.create_server()["ServerId"]
    deleted = {"v": False}

    def _cleanup():
        if not deleted["v"]:
            transfer.delete_server(ServerId=server_id)

    ctx.on_cleanup(_cleanup)

    described = transfer.describe_server(ServerId=server_id)["Server"]
    assert described["ServerId"] == server_id, (
        f"DescribeServer on the just-created server returned ServerId "
        f"{described['ServerId']!r}, expected {server_id!r}"
    )

    transfer.delete_server(ServerId=server_id)
    deleted["v"] = True

    code, message = _err(lambda: transfer.start_server(ServerId=server_id))
    assert code == "ResourceNotFoundException", (
        f"StartServer on the now-deleted (but once real) server {server_id} must be "
        f"rejected with ResourceNotFoundException -- proving the negative path is "
        f"reference-integrity, not malformed-ID special-casing -- got {code!r}"
    )
    assert message == "Unknown server", f"unexpected ResourceNotFoundException message {message!r}"

    code, message = _err(lambda: transfer.stop_server(ServerId=server_id))
    assert code == "ResourceNotFoundException", (
        f"StopServer on the now-deleted (but once real) server {server_id} must be "
        f"rejected with ResourceNotFoundException, got {code!r}"
    )
    assert message == "Unknown server", f"unexpected ResourceNotFoundException message {message!r}"

    code, message = _err(lambda: transfer.describe_server(ServerId=server_id))
    assert code == "ResourceNotFoundException", (
        f"DescribeServer on the now-deleted (but once real) server {server_id} must be "
        f"rejected with ResourceNotFoundException, got {code!r}"
    )
    assert message == "Unknown server", f"unexpected ResourceNotFoundException message {message!r}"


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        "expected a ClientError but the call succeeded -- an over-permissive target "
        "must not turn acceptance into a silent None/code mismatch"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

