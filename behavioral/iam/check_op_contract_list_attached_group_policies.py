"""op-contract-listAttachedGroupPolicies."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listAttachedGroupPolicies"
GROUP = "error-semantics"
SERVICES = ["iam"]

MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
MANAGED_POLICY_NAME = "AmazonS3ReadOnlyAccess"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAttachedGroupPolicies reflects exactly the managed policies attached to the
    group, with correct PolicyName/PolicyArn pairs; listing for a group that doesn't exist
    yields NoSuchEntityException."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-listagp-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    empty = iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
    assert empty == [], f"expected no attached policies on a fresh group, got {empty!r}"

    iam.attach_group_policy(GroupName=group_name, PolicyArn=MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_group_policy(GroupName=group_name, PolicyArn=MANAGED_POLICY_ARN))

    attached = iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
    assert len(attached) == 1, f"expected exactly 1 attached policy, got {attached!r}"
    assert attached[0]["PolicyArn"] == MANAGED_POLICY_ARN, (
        f"expected PolicyArn {MANAGED_POLICY_ARN!r}, got {attached[0]['PolicyArn']!r}"
    )
    assert attached[0]["PolicyName"] == MANAGED_POLICY_NAME, (
        f"expected PolicyName {MANAGED_POLICY_NAME!r}, got {attached[0]['PolicyName']!r}"
    )

    missing_group = ctx.unique_name("sim2real-listagp-missing-")
    code, message = _error(lambda: iam.list_attached_group_policies(GroupName=missing_group))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The group with name {missing_group} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    that lists policies for a group it never created is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected NoSuchEntity for a nonexistent group, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
