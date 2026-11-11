"""create-duplicate-user."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-duplicate-user"
GROUP = 'errors'
SERVICES = ['iam']

ERR_ENTITY_ALREADY_EXISTS = "EntityAlreadyExists"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a user with an existing name raises EntityAlreadyExists, the rejected duplicate
    call leaves the original user's identity untouched, and once that user is gone the identical
    CreateUser call succeeds again."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-user-")
    original_id = iam.create_user(UserName=name, Path="/")["User"]["UserId"]
    ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))

    try:
        iam.create_user(UserName=name)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_ENTITY_ALREADY_EXISTS, (
        f"expected {ERR_ENTITY_ALREADY_EXISTS}, got {code!r}"
    )
    assert message == f"User with name {name} already exists.", (
        f"expected the exact EntityAlreadyExists message AWS returns, got {message!r}"
    )

    # Independent read: the rejected duplicate must not have altered the original user.
    current_id = iam.get_user(UserName=name)["User"]["UserId"]
    assert current_id == original_id, (
        f"rejected duplicate CreateUser must not alter the original user: "
        f"expected UserId {original_id!r}, got {current_id!r}"
    )

    # Restore: once the original is gone, the identical call must succeed again, and IAM must
    # mint a fresh UserId rather than reusing the deleted one's.
    iam.delete_user(UserName=name)
    recreated_id = iam.create_user(UserName=name, Path="/")["User"]["UserId"]
    assert recreated_id != original_id, (
        f"expected a freshly minted UserId after recreation, got the original {original_id!r} again"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
