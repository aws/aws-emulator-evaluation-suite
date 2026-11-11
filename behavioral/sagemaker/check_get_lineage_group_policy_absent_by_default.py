"""get-lineage-group-policy-absent-by-default."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-lineage-group-policy-absent-by-default"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLineageGroupPolicy on an existing lineage group with no resource policy
    succeeds with ResourcePolicy "{}" rather than ResourceNotFound.
    """
    sm = ctx.client("sagemaker")

    lineage_group_name = _default_lineage_group_name(sm, ctx)

    # Positive control: the same lineage group is real and reachable via an independent
    # read, so the empty policy below is specifically the *policy's* absence -- not a
    # symptom of the group itself being unreachable.
    desc = sm.describe_lineage_group(LineageGroupName=lineage_group_name)
    assert desc["LineageGroupName"] == lineage_group_name, (
        f"expected DescribeLineageGroup to confirm {lineage_group_name!r}, got "
        f"{desc.get('LineageGroupName')!r}"
    )

    resp = sm.get_lineage_group_policy(LineageGroupName=lineage_group_name)
    assert resp["ResourcePolicy"] == "{}", (
        "expected GetLineageGroupPolicy to succeed with an empty ('{}') resource "
        f"policy document for a lineage group with nothing attached, got "
        f"{resp.get('ResourcePolicy')!r}"
    )


def _default_lineage_group_name(sm, ctx):
    """The account's default lineage group, provisioned by one throwaway Artifact (deleted at
    teardown) when ListLineageGroups lists none; SageMaker has no public CreateLineageGroup."""
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

    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while True:
        groups = sm.list_lineage_groups().get("LineageGroupSummaries", [])
        if groups:
            return groups[0]["LineageGroupName"]
        if time.monotonic() >= deadline:
            left = ctx.time_left()
            if left is not None and left <= 6.0:
                raise TimeoutError("default lineage group: the run budget ended first; not graded")
            raise AssertionError(
                "ListLineageGroups is still empty after creating a lineage artifact in "
                "this account/region, which on real AWS is enough to provision the "
                "account's default lineage group; there is nothing to probe "
                "GetLineageGroupPolicy against."
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
