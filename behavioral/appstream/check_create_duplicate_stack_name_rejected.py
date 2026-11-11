"""create-duplicate-stack-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-duplicate-stack-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with a Name that already exists is rejected with
    ResourceAlreadyExistsException; the original stack's attributes are untouched, and
    creating a stack with a distinct name (the positive control) succeeds."""
    appstream = ctx.client("appstream")

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    appstream.create_stack(Name=stack_name, Description="original-description")
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    code, message = _error(
        lambda: appstream.create_stack(Name=stack_name, Description="second-attempt-description")
    )
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r}"
    expected_message = (
        f"The stack {stack_name} for account {ctx.account}  already exists. "
        f"Use a unique name within an AWS region in your AWS account."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original stack's Description was not overwritten by the loser
    described = appstream.describe_stacks(Names=[stack_name])["Stacks"][0]
    assert described["Description"] == "original-description", (
        f"expected Description='original-description', got {described['Description']!r}"
    )

    # positive control: a distinct name succeeds
    other_name = ctx.unique_name("sim2real-appstream-stack-other-")
    appstream.create_stack(Name=other_name)
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=other_name))
    described_other = appstream.describe_stacks(Names=[other_name])["Stacks"]
    assert len(described_other) == 1, f"expected exactly 1 stack named {other_name!r}, got {described_other!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the botocore error it raises. An unexpected SUCCESS
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
