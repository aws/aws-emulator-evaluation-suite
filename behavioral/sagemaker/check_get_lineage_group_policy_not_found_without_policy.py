"""get-lineage-group-policy-not-found-without-policy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-lineage-group-policy-not-found-without-policy"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLineageGroupPolicy on a lineage group without a policy returns the empty object '{}'.

    DescribeLineageGroup on the same group is the positive control that the group is reachable.
    """
    sm = ctx.client("sagemaker")

    lineage_group_name = _default_lineage_group_name(sm, ctx)

    desc = sm.describe_lineage_group(LineageGroupName=lineage_group_name)
    assert desc["LineageGroupName"] == lineage_group_name, (
        f"positive control failed: DescribeLineageGroup returned "
        f"{desc.get('LineageGroupName')!r} for {lineage_group_name!r}"
    )

    resp = sm.get_lineage_group_policy(LineageGroupName=lineage_group_name)
    assert resp["ResourcePolicy"] == "{}", (
        f"expected the empty-policy sentinel '{{}}' for a lineage group with no "
        f"attached resource policy, got {resp['ResourcePolicy']!r}"
    )


def _default_lineage_group_name(sm, ctx):
    """SageMaker has no public CreateLineageGroup: the account's one default lineage
    group is provisioned lazily, on the first lineage-tracking entity ever created in
    the account/region -- a never-touched account has none. Trigger that provisioning
    with a throwaway Artifact (deleted immediately; the lineage group itself has no
    delete operation and persists as an account-global singleton, so this is a one-time,
    zero-cost side effect rather than a leak) and adopt whatever ListLineageGroups then
    reports, rather than assuming it was already there.
    """
    groups = sm.list_lineage_groups().get("LineageGroupSummaries", [])
    if groups:
        return groups[0]["LineageGroupName"]

    name = ctx.unique_name("sim2real-lineage-trigger-")
    created = sm.create_artifact(
        ArtifactName=name,
        Source={"SourceUri": f"s3://sim2real-lineage-trigger/{name}"},
        ArtifactType="DataSet",
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_artifact(ArtifactArn=created["ArtifactArn"]))

    groups = sm.list_lineage_groups().get("LineageGroupSummaries", [])
    if not groups:
        raise AssertionError(
            "ListLineageGroups is still empty after creating a lineage artifact in "
            "this account/emulator, which on real AWS is enough to provision the "
            "account's default lineage group; there is nothing to probe "
            "GetLineageGroupPolicy against."
        )
    return groups[0]["LineageGroupName"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
