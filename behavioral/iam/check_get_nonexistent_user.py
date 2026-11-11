"""get-nonexistent-user."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-nonexistent-user"
GROUP = 'errors'
SERVICES = ['iam']

ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUser on a never-created name fails with NoSuchEntity and its exact message, while a
    created user is returned; after that user is deleted, GetUser and DeleteUser on it fail the
    same way."""
    iam = ctx.client("iam")

    real_name = ctx.unique_name("sim2real-behav-realuser-")
    iam.create_user(UserName=real_name)
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_user(UserName=real_name)))

    resp = iam.get_user(UserName=real_name)
    assert resp["User"]["UserName"] == real_name, (
        f"positive control: expected GetUser({real_name}) to return that UserName, "
        f"got {resp['User'].get('UserName')!r}"
    )

    iam.delete_user(UserName=real_name)

    expected = f"The user with name {real_name} cannot be found."
    code_deleted, message = _error(lambda: iam.get_user(UserName=real_name))
    assert code_deleted == ERR_NO_SUCH_ENTITY, (
        f"GetUser on deleted user: expected {ERR_NO_SUCH_ENTITY}, got {code_deleted}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code_deleted_mutation, message = _error(lambda: iam.delete_user(UserName=real_name))
    assert code_deleted_mutation == ERR_NO_SUCH_ENTITY, (
        f"DeleteUser on already-deleted user: expected {ERR_NO_SUCH_ENTITY}, got {code_deleted_mutation}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    ghost_name = ctx.unique_name("sim2real-behav-ghost-user-")
    code_never_existed, message = _error(lambda: iam.get_user(UserName=ghost_name))
    assert code_never_existed == ERR_NO_SUCH_ENTITY, (
        f"GetUser on a name that was never created: expected {ERR_NO_SUCH_ENTITY}, "
        f"got {code_never_existed}"
    )
    expected = f"The user with name {ghost_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
