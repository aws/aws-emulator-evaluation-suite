"""op-contract-create-group-duplicate-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-group-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup stores Description and Precedence as GetGroup reads them, a duplicate GroupName fails
    with GroupExistsException and its exact message without changing the group, and after deletion
    GetGroup is not found and the name can be created again."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    group_name = ctx.unique_name("sim2real-group-")
    created = idp.create_group(
        UserPoolId=pool_id,
        GroupName=group_name,
        Description="sim2real test group",
        Precedence=7,
    )["Group"]
    assert created["GroupName"] == group_name
    assert created["UserPoolId"] == pool_id
    assert created["Description"] == "sim2real test group"
    assert created["Precedence"] == 7

    fetched = idp.get_group(UserPoolId=pool_id, GroupName=group_name)["Group"]
    assert fetched["Description"] == "sim2real test group"
    assert fetched["Precedence"] == 7

    code, message = _error(
        lambda: idp.create_group(UserPoolId=pool_id, GroupName=group_name, Description="dup")
    )
    assert code == "GroupExistsException", f"expected GroupExistsException, got {code}"
    assert message == "A group with the name already exists.", (
        f"expected the exact duplicate-group message, got {message!r}"
    )

    # Effect absent: the rejected duplicate must not have mutated the existing group.
    unaffected = idp.get_group(UserPoolId=pool_id, GroupName=group_name)["Group"]
    assert unaffected["Description"] == "sim2real test group", (
        f"duplicate rejection mutated Description, got {unaffected.get('Description')!r}"
    )
    assert unaffected["Precedence"] == 7, (
        f"duplicate rejection mutated Precedence, got {unaffected.get('Precedence')!r}"
    )

    # Restore: once the original group is gone, the identical GroupName is accepted again.
    idp.delete_group(UserPoolId=pool_id, GroupName=group_name)
    gone, gone_message = _error(lambda: idp.get_group(UserPoolId=pool_id, GroupName=group_name))
    assert gone == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {gone}"
    assert gone_message == "Group not found.", (
        f"expected the exact deleted-group message, got {gone_message!r}"
    )

    idp.create_group(
        UserPoolId=pool_id, GroupName=group_name, Description="restored", Precedence=2
    )
    restored = idp.get_group(UserPoolId=pool_id, GroupName=group_name)["Group"]
    assert restored["Description"] == "restored", (
        f"expected restored Description, got {restored.get('Description')!r}"
    )
    assert restored["Precedence"] == 2, f"expected Precedence 2, got {restored.get('Precedence')}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
