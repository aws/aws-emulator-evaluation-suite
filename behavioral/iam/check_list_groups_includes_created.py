"""list-groups-includes-created."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "list-groups-includes-created"
GROUP = 'groups'
SERVICES = ['iam']


def _err_code(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGroups includes a group we just created, with matching identity fields;
    after DeleteGroup it is gone from both ListGroups and GetGroup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-grp-")
    created = iam.create_group(GroupName=name, Path="/")["Group"]

    def _cleanup():
        try:
            iam.delete_group(GroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    paginator = iam.get_paginator("list_groups")
    match = None
    for page in paginator.paginate():
        for group in page["Groups"]:
            if group["GroupName"] == name:
                match = group
                break
        if match:
            break
    assert match is not None, f"Group {name} not found in ListGroups"
    assert match["Arn"] == created["Arn"], f"Arn mismatch: {match['Arn']} != {created['Arn']}"
    assert match["GroupId"] == created["GroupId"], (
        f"GroupId mismatch: {match['GroupId']} != {created['GroupId']}"
    )

    iam.delete_group(GroupName=name)
    code, message = _err_code(lambda: iam.get_group(GroupName=name))
    assert code == "NoSuchEntity", f"expected group gone after delete, got {code}"
    expected_message = f"The group with name {name} cannot be found."
    assert message == expected_message, (
        f"GetGroup on the deleted group must carry AWS's exact message {expected_message!r}; "
        f"got {message!r}"
    )

    names_after = [
        g["GroupName"]
        for page in iam.get_paginator("list_groups").paginate()
        for g in page["Groups"]
    ]
    assert name not in names_after, f"deleted group {name} still present in ListGroups"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
