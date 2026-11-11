"""delete-room-removes-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-room-removes-resource"
GROUP = "state"
SERVICES = ["ivschat"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, the call succeeded instead")


def _delete_if_present(ivschat, arn):
    from botocore.exceptions import ClientError

    try:
        ivschat.delete_room(identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteRoom, GetRoom on the same identifier fails with ResourceNotFoundException --
    the room is actually gone, not just soft-hidden -- and UpdateRoom against the same dead
    identifier is rejected too, proving the id is unusable for mutations, not just reads."""
    ivschat = ctx.client("ivschat")
    name = ctx.unique_name("sim2real-ivschat-room")
    created = ivschat.create_room(name=name)
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_if_present(ivschat, arn))

    ivschat.delete_room(identifier=arn)

    code, message = _error(lambda: ivschat.get_room(identifier=arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetRoom on a deleted room, got {code}"
    )
    assert message == f"Resource: {arn} not found", f"GetRoom message: {message!r}"

    update_code, update_message = _error(
        lambda: ivschat.update_room(identifier=arn, name=ctx.unique_name("sim2real-ivschat-renamed"))
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateRoom on a deleted room, got {update_code}"
    )
    assert update_message == f"Resource: {arn} not found", (
        f"UpdateRoom message: {update_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
