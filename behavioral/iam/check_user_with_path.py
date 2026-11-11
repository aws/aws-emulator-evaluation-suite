"""user-with-path."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "user-with-path"
GROUP = 'path_handling'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser with Path includes path in ARN and GetUser response."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-user-")
    path = "/sim2real/testing/"
    iam.create_user(UserName=name, Path=path)
    ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))
    user = iam.get_user(UserName=name)["User"]
    assert user["Path"] == path, f"GetUser must echo the Path, got {user['Path']!r}"
    expected_arn = f"arn:aws:iam::{account}:user{path}{name}"
    assert user["Arn"] == expected_arn, (
        f"user ARN must compose path and name exactly: {user['Arn']!r} != {expected_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
