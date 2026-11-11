"""create-protection-group-unprotected-member-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-protection-group-unprotected-member-not-found"
GROUP = "error-semantics"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProtectionGroup with Pattern=ARBITRARY and an unprotected member ARN is rejected with
    InvalidParameterException and the exact message and creates no group, while a Pattern=ALL create succeeds
    or fails only for the missing subscription.
    """
    shield = ctx.client("shield")
    group_id = ctx.unique_name("sim2real-pg-")
    member_arn = f"arn:aws:ec2:{ctx.region}:111122223333:eip-allocation/eipalloc-{'0' * 17}"

    def _create():
        shield.create_protection_group(
            ProtectionGroupId=group_id,
            Aggregation="SUM",
            Pattern="ARBITRARY",
            Members=[member_arn],
        )

    ctx.on_cleanup(lambda: _best_effort_delete(shield, group_id))
    code, message = _error_code(_create)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "One or more protection group input fields are incorrect.", f"unexpected message {message!r}"

    # Effect absent: the group must not actually exist after the rejected create.
    list_code, list_message = _error_code(lambda: shield.describe_protection_group(ProtectionGroupId=group_id))
    assert list_code == "ResourceNotFoundException", (
        f"protection group should not have been created, but describe returned {list_code!r}"
    )
    assert list_message == "The referenced protection-group does not exist.", (
        f"unexpected message {list_message!r}"
    )

    # Differential control: Pattern=ALL takes neither Members nor ResourceType, so it either succeeds
    # (subscribed) or is refused for the missing subscription; InvalidParameterException here too
    # would mean the rejection above is a blanket refusal, not member validation.
    control_group_id = ctx.unique_name("sim2real-pg-ctrl-")
    ctx.on_cleanup(lambda: _best_effort_delete(shield, control_group_id))
    try:
        shield.create_protection_group(ProtectionGroupId=control_group_id, Aggregation="SUM", Pattern="ALL")
    except ClientError as exc:
        control_code = exc.response["Error"]["Code"]
        control_message = exc.response["Error"].get("Message")
        assert control_code == "ResourceNotFoundException", (
            "a structurally-valid CreateProtectionGroup(Pattern=ALL) must only be refused for the missing "
            f"subscription, got {control_code!r}"
        )
        assert control_message == "The subscription does not exist.", f"unexpected message {control_message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _best_effort_delete(shield, group_id):
    try:
        shield.delete_protection_group(ProtectionGroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
