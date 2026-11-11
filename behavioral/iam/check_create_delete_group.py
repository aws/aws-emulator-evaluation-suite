"""create-delete-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-delete-group"
GROUP = 'groups'
SERVICES = ['iam']

ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup -> DeleteGroup: GetGroup and a second DeleteGroup on the same
    name both return NoSuchEntity, and recreating that freed name mints a genuinely
    new GroupId rather than resurrecting the deleted one."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-grp-")
    created = iam.create_group(GroupName=name, Path="/")
    group_id = created["Group"]["GroupId"]
    ctx.on_cleanup(lambda n=name: iam.delete_group(GroupName=n))
    iam.delete_group(GroupName=name)

    missing_group = f"The group with name {name} cannot be found."
    get_code, get_msg = _error(lambda: iam.get_group(GroupName=name))
    assert get_code == ERR_NO_SUCH_ENTITY, f"GetGroup: expected {ERR_NO_SUCH_ENTITY}, got {get_code}"
    assert get_msg == missing_group, f"GetGroup message: {get_msg!r}"

    delete_code, delete_msg = _error(lambda: iam.delete_group(GroupName=name))
    assert delete_code == ERR_NO_SUCH_ENTITY, (
        f"DeleteGroup on an already-deleted group: expected {ERR_NO_SUCH_ENTITY}, got {delete_code}"
    )
    assert delete_msg == missing_group, f"DeleteGroup on an already-deleted group message: {delete_msg!r}"

    recreated = iam.create_group(GroupName=name, Path="/")
    assert recreated["Group"]["GroupId"] != group_id, (
        "recreating a freed group name must mint a new GroupId, not resurrect the old one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
