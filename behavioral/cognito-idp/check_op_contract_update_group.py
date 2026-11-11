"""op-contract-update-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-group"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup persists Description/Precedence changes visible via GetGroup, and is
    rejected for a group that doesn't exist in the pool."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-updgrp-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_idempotent(cognito, pool_id))

    group_name = ctx.unique_name("sim2real-group-")
    created = cognito.create_group(
        UserPoolId=pool_id, GroupName=group_name, Description="initial", Precedence=10
    )["Group"]

    updated = cognito.update_group(
        UserPoolId=pool_id,
        GroupName=group_name,
        Description="updated-description",
        Precedence=5,
    )["Group"]
    assert updated["Description"] == "updated-description", updated
    assert updated["Precedence"] == 5, updated
    assert updated["LastModifiedDate"] >= created["LastModifiedDate"], updated

    fetched = cognito.get_group(UserPoolId=pool_id, GroupName=group_name)["Group"]
    assert fetched["Description"] == "updated-description", fetched
    assert fetched["Precedence"] == 5, fetched

    # Error boundary: updating a group that was never created is rejected.
    code, message = _error(
        lambda: cognito.update_group(
            UserPoolId=pool_id, GroupName="does-not-exist-group", Description="x"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code}"
    )
    expected = "Group not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Delete proves gone and unusable: an independent read 404s, and a further mutation on the
    # dead pool also fails.
    cognito.delete_user_pool(UserPoolId=pool_id)
    get_code, get_message = _error(lambda: cognito.describe_user_pool(UserPoolId=pool_id))
    assert get_code == "ResourceNotFoundException", (
        f"expected pool {pool_id} gone after delete, got {get_code}"
    )
    pool_gone = f"User pool {pool_id} does not exist."
    assert get_message == pool_gone, f"expected message {pool_gone!r}, got {get_message!r}"
    update_code, update_message = _error(
        lambda: cognito.update_group(UserPoolId=pool_id, GroupName=group_name, Description="y")
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateGroup on deleted pool {pool_id} to 404, got {update_code}"
    )
    assert update_message == pool_gone, f"expected message {pool_gone!r}, got {update_message!r}"


def _delete_pool_idempotent(cognito, pool_id):
    from botocore.exceptions import ClientError

    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, but call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
