"""tag-user."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "tag-user"
GROUP = 'tags'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagUser -> ListUserTags returns exactly the tag; once the user is deleted, ListUserTags on it fails NoSuchEntity."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda n=user: _delete_user_if_present(iam, n))
    iam.tag_user(
        UserName=user,
        Tags=[{"Key": "team", "Value": "sim2real"}],
    )
    resp = iam.list_user_tags(UserName=user)
    tag_map = {t["Key"]: t["Value"] for t in resp["Tags"]}
    assert tag_map == {"team": "sim2real"}, f"expected {{'team': 'sim2real'}}, got {tag_map}"

    iam.delete_user(UserName=user)
    code, message = _error(lambda: iam.list_user_tags(UserName=user))
    assert code == "NoSuchEntity", f"expected NoSuchEntity after delete, got {code}"
    expected = f"The user with name {user} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _delete_user_if_present(iam, user_name):
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
