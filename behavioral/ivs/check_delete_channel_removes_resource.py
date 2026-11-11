"""delete-channel-removes-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-channel-removes-resource"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChannel is a terminal deletion: a subsequent GetChannel raises
    ResourceNotFoundException rather than returning stale data, and the dead ARN
    also rejects a mutation (UpdateChannel) rather than silently accepting it."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    arn = ivs.create_channel(name=name, tags={"purpose": "sim2real"})["channel"]["arn"]

    deleted = {"done": False}

    def _cleanup():
        from botocore.exceptions import ClientError

        if not deleted["done"]:
            try:
                ivs.delete_channel(arn=arn)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    ivs.delete_channel(arn=arn)
    deleted["done"] = True

    error = _client_error(lambda: ivs.get_channel(arn=arn))
    assert error["Code"] == "ResourceNotFoundException", (
        f"GetChannel on a deleted channel: expected ResourceNotFoundException, got {error!r}"
    )
    assert error["Message"] == f"Resource: {arn} not found", (
        f"unexpected GetChannel not-found message: {error['Message']!r}"
    )

    update_error = _client_error(
        lambda: ivs.update_channel(arn=arn, name=ctx.unique_name("sim2real-ivs-chan-upd-"))
    )
    assert update_error["Code"] == "ResourceNotFoundException", (
        f"UpdateChannel on a deleted channel: expected ResourceNotFoundException, got {update_error!r}"
    )
    assert update_error["Message"] == f"Resource: {arn} not found", (
        f"unexpected UpdateChannel not-found message: {update_error['Message']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
