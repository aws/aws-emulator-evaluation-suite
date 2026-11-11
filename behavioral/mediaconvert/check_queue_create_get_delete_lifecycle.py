"""queue-create-get-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-create-get-delete-lifecycle"
GROUP = "control-plane"
SERVICES = ["mediaconvert"]
NOT_FOUND_MESSAGE = "The resource you specified in name was not found."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQueue returns an ACTIVE CUSTOM queue whose fields GetQueue returns; after DeleteQueue both
    GetQueue and UpdateQueue fail NotFoundException with the exact message, and the freed name can be
    created again."""
    mc = ctx.client("mediaconvert")
    name = ctx.unique_name("sim2real-mc-queue-")

    def _cleanup():
        try:
            mc.delete_queue(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    created = mc.create_queue(
        Name=name,
        Description="sim2real behavioral check",
        Tags={"sim2real-check": CHECK},
    )["Queue"]
    assert created["Name"] == name, f"expected Name {name!r}, got {created['Name']!r}"
    assert created["Status"] == "ACTIVE", f"expected Status ACTIVE, got {created['Status']!r}"
    assert created["Type"] == "CUSTOM", f"expected Type CUSTOM, got {created['Type']!r}"

    got = mc.get_queue(Name=name)["Queue"]
    assert got["Arn"] == created["Arn"], f"expected Arn {created['Arn']!r}, got {got['Arn']!r}"
    assert got["Description"] == "sim2real behavioral check", (
        f"expected Description to persist, got {got['Description']!r}"
    )
    assert got["Status"] == "ACTIVE", f"expected Status ACTIVE, got {got['Status']!r}"

    mc.delete_queue(Name=name)
    code, message = _error(lambda: mc.get_queue(Name=name))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert message == NOT_FOUND_MESSAGE, f"expected message {NOT_FOUND_MESSAGE!r}, got {message!r}"

    # a mutation on the dead id also fails, not just a read
    update_code, update_message = _error(lambda: mc.update_queue(Name=name, Description="post-delete"))
    assert update_code == "NotFoundException", (
        f"expected NotFoundException for UpdateQueue on deleted queue, got {update_code!r}"
    )
    assert update_message == NOT_FOUND_MESSAGE, (
        f"expected message {NOT_FOUND_MESSAGE!r}, got {update_message!r}"
    )

    # the identifier is reusable once freed; cleanup deletes it again
    recreated = mc.create_queue(Name=name, Tags={"sim2real-check": CHECK})["Queue"]
    assert recreated["Name"] == name, f"expected reused Name {name!r}, got {recreated['Name']!r}"
    assert recreated["Status"] == "ACTIVE", (
        f"expected recreated queue Status ACTIVE, got {recreated['Status']!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
