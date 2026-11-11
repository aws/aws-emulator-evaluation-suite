"""delete-default-queue-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-default-queue-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconvert"]
NOT_FOUND_MESSAGE = "The resource you specified in name was not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The account's built-in "Default" queue is a protected SYSTEM resource and DeleteQueue on
    it must be rejected; it must still exist afterwards. A user-created CUSTOM queue, by
    contrast, deletes cleanly (the positive control)."""
    mc = ctx.client("mediaconvert")

    code, message = _error(lambda: mc.delete_queue(Name="Default"))
    assert code == "ForbiddenException", f"expected ForbiddenException, got {code!r}"
    expected = "You specified an invalid value for name. You are not allowed to delete system resources."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    got = mc.get_queue(Name="Default")["Queue"]
    assert got["Name"] == "Default", f"expected the Default queue to still exist, got {got['Name']!r}"
    assert got["Type"] == "SYSTEM", f"expected Default queue Type SYSTEM, got {got['Type']!r}"

    # positive control: a custom queue deletes cleanly, and the dead name is both
    # unreadable and unusable afterwards (proves "gone", not just "unlisted")
    name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=name)
    ctx.on_cleanup(lambda: _delete_queue_if_present(mc, name))
    mc.delete_queue(Name=name)
    code2, message2 = _error(lambda: mc.get_queue(Name=name))
    assert code2 == "NotFoundException", f"expected the deleted queue to read NotFoundException, got {code2!r}"
    assert message2 == NOT_FOUND_MESSAGE, f"expected message {NOT_FOUND_MESSAGE!r}, got {message2!r}"
    code3, message3 = _error(lambda: mc.update_queue(Name=name, Status="PAUSED"))
    assert code3 == "NotFoundException", (
        f"expected a mutation on the already-gone queue to also fail NotFoundException, got {code3!r}"
    )
    assert message3 == NOT_FOUND_MESSAGE, f"expected message {NOT_FOUND_MESSAGE!r}, got {message3!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_queue_if_present(mc, name: str) -> None:
    try:
        mc.delete_queue(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
