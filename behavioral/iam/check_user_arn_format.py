"""user-arn-format."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "user-arn-format"
GROUP = 'user_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """User ARN follows arn:aws:iam::<account>:user/<path><name>."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=name, Path="/")
    ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))
    user = iam.get_user(UserName=name)["User"]
    arn = user["Arn"]
    expected = f"arn:aws:iam::{account}:user/{name}"
    assert arn == expected, f"ARN {arn!r} does not equal {expected!r}"
    assert arn.split(":")[3] == "", f"IAM is global so the ARN region field must be empty, got {arn!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
