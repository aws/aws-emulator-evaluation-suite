"""create-get-user."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-get-user"
GROUP = 'user_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser -> GetUser returns consistent configuration."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=name, Path="/")
    ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))
    resp = iam.get_user(UserName=name)
    user = resp["User"]
    assert user["UserName"] == name, f"expected UserName {name!r}, got {user['UserName']!r}"
    expected_arn = f"arn:aws:iam::{account_id}:user/{name}"
    assert user["Arn"] == expected_arn, f"expected Arn {expected_arn!r}, got {user['Arn']!r}"
    assert user["Path"] == "/", f"expected Path '/', got {user['Path']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
