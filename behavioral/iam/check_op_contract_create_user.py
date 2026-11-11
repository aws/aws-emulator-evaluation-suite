"""op-contract-create-user."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-user"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser returns the name, default Path / and a matching Arn; a duplicate fails
    with EntityAlreadyExists and its exact message leaving the user, and after delete (exact
    NoSuchEntity on GetUser and DeleteUser) the name is reused with a new UserId."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-user-")
    created = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    assert created["UserName"] == user_name, f"expected UserName={user_name!r}, got {created.get('UserName')!r}"
    assert created["Path"] == "/", f"expected default Path '/', got {created.get('Path')!r}"
    assert created["Arn"].endswith(f":user/{user_name}"), (
        f"Arn {created['Arn']!r} does not end with :user/{user_name}"
    )

    fetched = iam.get_user(UserName=user_name)["User"]
    assert fetched["UserId"] == created["UserId"], (
        f"independent GetUser returned UserId {fetched['UserId']!r}, expected {created['UserId']!r}"
    )

    code, message = _error(lambda: iam.create_user(UserName=user_name))
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code}"
    expected = f"User with name {user_name} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = iam.get_user(UserName=user_name)["User"]
    assert unchanged["UserId"] == created["UserId"], (
        "rejected duplicate CreateUser must not mutate or replace the existing user, but "
        f"UserId changed from {created['UserId']!r} to {unchanged['UserId']!r}"
    )

    iam.delete_user(UserName=user_name)
    gone_code, gone_message = _error(lambda: iam.get_user(UserName=user_name))
    assert gone_code == "NoSuchEntity", f"expected NoSuchEntity for GetUser after delete, got {gone_code}"
    expected = f"The user with name {user_name} cannot be found."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    redelete_code, redelete_message = _error(lambda: iam.delete_user(UserName=user_name))
    assert redelete_code == "NoSuchEntity", f"expected NoSuchEntity on double-delete, got {redelete_code}"
    expected = f"The user with name {user_name} cannot be found."
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"

    recreated = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]
    assert recreated["UserName"] == user_name, (
        f"expected recreated UserName={user_name!r}, got {recreated.get('UserName')!r}"
    )
    assert recreated["UserId"] != created["UserId"], (
        "a freed UserName must get a fresh UserId, not resurrect the deleted user's identity"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected an error, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
