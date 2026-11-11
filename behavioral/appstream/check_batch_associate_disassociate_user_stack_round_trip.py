"""batch-associate-disassociate-user-stack-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-associate-disassociate-user-stack-round-trip"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchAssociateUserStack links a user pool identity to a stack (visible via
    DescribeUserStackAssociations); BatchDisassociateUserStack removes it again."""
    appstream = ctx.client("appstream")

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    appstream.create_stack(Name=stack_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    user_name = f"{ctx.unique_name('sim2real-appstream-user-')}@example.com"
    auth_type = "USERPOOL"
    appstream.create_user(UserName=user_name, AuthenticationType=auth_type, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: appstream.delete_user(UserName=user_name, AuthenticationType=auth_type))

    # allow for eventual consistency: the user must be visible before it can be associated
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        users = appstream.describe_users(AuthenticationType=auth_type)["Users"]
        if any(u["UserName"] == user_name for u in users):
            break
        time.sleep(2)
    else:
        raise AssertionError(f"user {user_name} did not become visible via describe_users within 30s")

    association = {"StackName": stack_name, "UserName": user_name, "AuthenticationType": auth_type}

    result = appstream.batch_associate_user_stack(UserStackAssociations=[association])
    assert result["errors"] == [], f"expected no errors associating {user_name} with {stack_name}, got {result['errors']}"

    assocs = appstream.describe_user_stack_associations(
        StackName=stack_name, UserName=user_name, AuthenticationType=auth_type
    )["UserStackAssociations"]
    assert any(a["StackName"] == stack_name and a["UserName"] == user_name for a in assocs), (
        f"expected {user_name} associated with {stack_name} in describe_user_stack_associations, got {assocs}"
    )

    result = appstream.batch_disassociate_user_stack(UserStackAssociations=[association])
    assert result["errors"] == [], f"expected no errors disassociating {user_name} from {stack_name}, got {result['errors']}"

    assocs_after = appstream.describe_user_stack_associations(
        StackName=stack_name, UserName=user_name, AuthenticationType=auth_type
    )["UserStackAssociations"]
    assert not any(a["StackName"] == stack_name and a["UserName"] == user_name for a in assocs_after), (
        f"expected {user_name} no longer associated with {stack_name} after disassociate, got {assocs_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
