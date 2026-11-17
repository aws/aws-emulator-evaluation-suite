"""attach-group-policy-well-formed-nonexistent-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "attach-group-policy-well-formed-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]

_VALID_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachGroupPolicy rejects a well-formed PolicyArn in the caller's own account namespace
    that names no real customer-managed policy with the exact NoSuchEntity message, leaving no
    attachment; an AWS managed policy on the same group attaches cleanly."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-grp-attachunk-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    never_created_name = ctx.unique_name("sim2real-pol-never-created-")
    bogus_arn = f"arn:aws:iam::{ctx.account}:policy/{never_created_name}"

    code, message = _error(lambda: iam.attach_group_policy(GroupName=group_name, PolicyArn=bogus_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"Policy {bogus_arn} does not exist or is not attachable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected attach left no attachment on the group.
    attached = [
        p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
    ]
    assert attached == [], f"expected no attached policies after the rejected attach, got {attached}"

    # Positive control: a real AWS managed policy on the same group attaches cleanly.
    iam.attach_group_policy(GroupName=group_name, PolicyArn=_VALID_POLICY_ARN)
    attached_after = [
        p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
    ]
    assert attached_after == [_VALID_POLICY_ARN], (
        f"expected only {_VALID_POLICY_ARN} attached, got {attached_after}"
    )
    iam.detach_group_policy(GroupName=group_name, PolicyArn=_VALID_POLICY_ARN)


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a well-formed but nonexistent policy ARN, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
