"""delete-user."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-user"
GROUP = 'user_lifecycle'
SERVICES = ['iam']

ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUser removes the user: GetUser returns NoSuchEntity, a further mutation on the
    dead name also fails NoSuchEntity, and the freed username is reusable by a fresh CreateUser."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=name, Path="/")
    ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))
    iam.delete_user(UserName=name)

    code, code_msg = _client_error(lambda: iam.get_user(UserName=name))
    assert code == ERR_NO_SUCH_ENTITY, f"expected NoSuchEntity after delete, got {code}"
    assert code_msg == f"The user with name {name} cannot be found.", f"unexpected error message {code_msg!r}"

    mutate_code, mutate_code_msg = _client_error(lambda: iam.update_user(UserName=name, NewPath="/renamed/"))
    assert mutate_code == ERR_NO_SUCH_ENTITY, (
        f"mutation on a deleted user should still be NoSuchEntity, got {mutate_code}"
    )
    assert mutate_code_msg == f"The user with name {name} cannot be found.", f"unexpected error message {mutate_code_msg!r}"

    iam.create_user(UserName=name, Path="/")
    recreated = iam.get_user(UserName=name)
    assert recreated["User"]["UserName"] == name, "freed username should be reusable by a fresh CreateUser"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
