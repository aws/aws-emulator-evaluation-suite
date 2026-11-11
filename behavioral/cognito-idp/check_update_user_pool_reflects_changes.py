"""update-user-pool-reflects-changes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "update-user-pool-reflects-changes"
GROUP = 'user-pool-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserPool persists changes visible on a subsequent DescribeUserPool, leaves
    unrelated fields untouched, and the deleted pool is gone and unusable afterward."""
    c = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-cip-pool-")
    created = c.create_user_pool(PoolName=pool_name, UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]
    pool_id = created["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _delete_pool_if_present(c, _id))

    c.update_user_pool(
        UserPoolId=pool_id,
        AutoVerifiedAttributes=["email"],
    )
    desc = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert desc["AutoVerifiedAttributes"] == ["email"], (
        f"expected AutoVerifiedAttributes ['email'], got {desc.get('AutoVerifiedAttributes')}"
    )
    # Partial update: identity fields untouched by a call that only named AutoVerifiedAttributes.
    assert desc["Id"] == pool_id, f"expected Id {pool_id} unchanged, got {desc['Id']}"
    assert desc["Name"] == pool_name, f"expected Name {pool_name} unchanged, got {desc['Name']}"
    assert desc["LastModifiedDate"] >= created["CreationDate"], (
        "LastModifiedDate did not advance after UpdateUserPool"
    )

    c.delete_user_pool(UserPoolId=pool_id)
    try:
        result = c.describe_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code, message = error.get("Code"), error.get("Message")
    else:
        raise AssertionError(f"expected DescribeUserPool on a deleted pool to fail, got {result!r}")
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code}"
    )
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, (
        f"expected the exact {code} message {expected_message!r}, got {message!r}"
    )


def _delete_pool_if_present(c, pool_id):
    """The check deletes the pool itself; cleanup covers an early failure before that."""
    try:
        c.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
