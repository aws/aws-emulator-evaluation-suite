"""delete-server-nonexistent-resource-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-server-nonexistent-resource-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteServer on a well-formed nonexistent ServerId fails with ResourceNotFoundException
    "Unknown server" and leaves a real server describable; once that server is deleted,
    DescribeServer fails with the same code and message."""
    transfer = ctx.client("transfer")

    # Real, valid server used as setup + positive control.
    real_server_id = transfer.create_server(
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ServerId"]

    def _cleanup_real_server():
        try:
            transfer.delete_server(ServerId=real_server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_real_server)

    # Well-formed ServerId (matches ^s-([0-9a-f]{17})$) that was never created.
    bogus_server_id = "s-" + "0" * 17

    code, message = _error(lambda: transfer.delete_server(ServerId=bogus_server_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unknown server", f"unexpected not-found message: {message!r}"

    # Effect absent: the real server is unaffected by the rejected bogus delete.
    desc = transfer.describe_server(ServerId=real_server_id)["Server"]
    assert desc["ServerId"] == real_server_id, (
        f"expected real server {real_server_id} untouched, got {desc['ServerId']}"
    )

    # Positive control: deleting the real server succeeds and it becomes 404.
    transfer.delete_server(ServerId=real_server_id)
    code2, message2 = _error(lambda: transfer.describe_server(ServerId=real_server_id))
    assert code2 == "ResourceNotFoundException", f"expected 404 after real delete, got {code2}"
    assert message2 == "Unknown server", f"unexpected not-found message: {message2!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
