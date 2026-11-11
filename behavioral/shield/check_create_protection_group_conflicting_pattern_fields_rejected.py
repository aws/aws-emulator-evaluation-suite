"""create-protection-group-conflicting-pattern-fields-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-protection-group-conflicting-pattern-fields-rejected"
GROUP = "overly-permissive"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProtectionGroup with Pattern=BY_RESOURCE_TYPE plus Members is rejected with
    InvalidParameterException and the exact message and creates no group; the correct fields then either
    create the group or, unsubscribed, fail with the exact no-subscription ResourceNotFoundException.
    """
    shield = ctx.client("shield")

    bad_group_id = ctx.unique_name("sim2real-pg-bad-")
    fake_member_arn = f"arn:aws:ec2:{ctx.region}:111122223333:eip-allocation/eipalloc-{'0' * 17}"

    def _create_bad():
        shield.create_protection_group(
            ProtectionGroupId=bad_group_id,
            Aggregation="SUM",
            Pattern="BY_RESOURCE_TYPE",
            ResourceType="ELASTIC_IP_ALLOCATION",
            Members=[fake_member_arn],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    ctx.on_cleanup(lambda: _best_effort_delete(shield, bad_group_id))
    bad_code, bad_message = _error_code(_create_bad)
    assert bad_code == "InvalidParameterException", f"expected InvalidParameterException, got {bad_code!r}"
    assert bad_message == "One or more protection group input fields are incorrect.", (
        f"unexpected message {bad_message!r}"
    )

    not_found_code, not_found_message = _error_code(
        lambda: shield.describe_protection_group(ProtectionGroupId=bad_group_id)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected protection group must not exist, describe returned {not_found_code!r}"
    )
    assert not_found_message == "The referenced protection-group does not exist.", (
        f"unexpected message {not_found_message!r}"
    )

    # Positive control: the correct field combination for BY_RESOURCE_TYPE.
    good_group_id = ctx.unique_name("sim2real-pg-good-")

    def _create_good():
        shield.create_protection_group(
            ProtectionGroupId=good_group_id,
            Aggregation="SUM",
            Pattern="BY_RESOURCE_TYPE",
            ResourceType="ELASTIC_IP_ALLOCATION",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    try:
        _create_good()
    except ClientError as exc:
        # No active Shield Advanced subscription: the correct field combination is refused for the
        # missing subscription, a different code than the conflicting-fields rejection above, so
        # that rejection was about the fields and not a blanket refusal.
        good_code = exc.response["Error"]["Code"]
        good_message = exc.response["Error"].get("Message")
        assert good_code == "ResourceNotFoundException", (
            f"correct field combination unexpectedly rejected as {good_code!r}"
        )
        assert good_message == "The subscription does not exist.", f"unexpected message {good_message!r}"
    else:
        ctx.on_cleanup(lambda: _best_effort_delete(shield, good_group_id))
        described = shield.describe_protection_group(ProtectionGroupId=good_group_id)["ProtectionGroup"]
        assert described["ResourceType"] == "ELASTIC_IP_ALLOCATION"
        assert described["Pattern"] == "BY_RESOURCE_TYPE"


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
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
