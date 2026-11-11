"""op-contract-delete-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-group"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGroup removes the group (verified via GetGroup -> ResourceNotFoundException)
    and rejects deleting an already-deleted / nonexistent GroupName with
    ResourceNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    group_name = ctx.unique_name("sim2real-group-")
    idp.create_group(UserPoolId=pool_id, GroupName=group_name)
    idp.get_group(UserPoolId=pool_id, GroupName=group_name)  # exists pre-delete
    pre_delete_names = {g["GroupName"] for g in idp.list_groups(UserPoolId=pool_id)["Groups"]}
    assert group_name in pre_delete_names, f"expected {group_name} in ListGroups pre-delete, got {pre_delete_names}"

    resp = idp.delete_group(UserPoolId=pool_id, GroupName=group_name)
    body = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
    assert body == {}, f"expected an empty DeleteGroup response body, got {body}"

    code, message = _error(lambda: idp.get_group(UserPoolId=pool_id, GroupName=group_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException post-delete, got {code}"
    expected_message = "Group not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    post_delete_names = {g["GroupName"] for g in idp.list_groups(UserPoolId=pool_id)["Groups"]}
    assert group_name not in post_delete_names, f"expected {group_name} absent from ListGroups post-delete, got {post_delete_names}"

    code2, message2 = _error(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=group_name))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException on repeat delete, got {code2}"
    expected_message2 = "Group not found."
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
