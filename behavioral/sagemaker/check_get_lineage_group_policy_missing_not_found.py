"""get-lineage-group-policy-missing-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-lineage-group-policy-missing-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


_LINEAGE_GROUP_NAME = "sagemaker-default-lineage-group"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetLineageGroupPolicy on the account's default lineage group, which has no resource policy,
    succeeds with ResourcePolicy "{}" rather than ResourceNotFound; the check first creates a lineage
    entity so that the group exists.
    """
    sm = ctx.client("sagemaker")

    if not _lineage_group_exists(sm):
        bootstrap_name = ctx.unique_name("sim2real-behav-lineage-bootstrap-")
        sm.create_context(
            ContextName=bootstrap_name,
            Source={
                "SourceUri": f"s3://sim2real-behav-lineage/{bootstrap_name}",
                "SourceType": "Endpoint",
            },
            ContextType="Endpoint",
            Tags=[{"Key": "sim2real-behav", "Value": bootstrap_name}],
        )
        ctx.on_cleanup(lambda: sm.delete_context(ContextName=bootstrap_name))
        assert _lineage_group_exists(sm), (
            f"expected creating context {bootstrap_name!r} to provision the default "
            f"lineage group {_LINEAGE_GROUP_NAME!r}, but it still does not exist"
        )

    # Positive control: the group is real and describable through DescribeLineageGroup, a
    # different operation than the one under test below.
    desc = sm.describe_lineage_group(LineageGroupName=_LINEAGE_GROUP_NAME)
    assert desc["LineageGroupName"] == _LINEAGE_GROUP_NAME, (
        f"positive control failed: describing {_LINEAGE_GROUP_NAME!r} returned "
        f"{desc.get('LineageGroupName')!r}"
    )

    # The call under test: no policy has ever been attached (there is no public API that
    # could attach one), so GetLineageGroupPolicy succeeds with an empty policy document
    # rather than failing.
    policy = sm.get_lineage_group_policy(LineageGroupName=_LINEAGE_GROUP_NAME)
    assert policy["ResourcePolicy"] == "{}", (
        f"expected an empty ResourcePolicy document for a group with no attached policy, "
        f"got {policy['ResourcePolicy']!r}"
    )


def _lineage_group_exists(sm) -> bool:
    try:
        sm.describe_lineage_group(LineageGroupName=_LINEAGE_GROUP_NAME)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFound":
            return False
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
