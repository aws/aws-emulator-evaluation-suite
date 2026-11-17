"""list-association-versions-pagination-token-exactness."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-association-versions-pagination-token-exactness"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _create_command_document(ctx, ssm) -> str:
    name = ctx.unique_name("sim2real-behav-pg-doc-")
    content = json.dumps(
        {
            "schemaVersion": "2.2",
            "description": "sim2real behavioral test document",
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "echoStep",
                    "inputs": {"runCommand": ["echo sim2real"]},
                }
            ],
        }
    )
    ssm.create_document(
        Content=content,
        Name=name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAssociationVersions with MaxResults=2 over four versions returns a NextToken on the
    first page only, and the two pages together cover every version exactly once."""
    ssm = ctx.client("ssm")
    doc_name = _create_command_document(ctx, ssm)

    # A run-unique tag no managed node carries: the association targets no instance.
    no_node = [{"Key": "tag:sim2real-target", "Values": [ctx.unique_name("sim2real-no-node-")]}]
    created = ssm.create_association(
        Name=doc_name,
        Targets=no_node,
        ScheduleExpression="rate(30 minutes)",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AssociationDescription"]
    assoc_id = created["AssociationId"]
    ctx.on_cleanup(lambda: ssm.delete_association(AssociationId=assoc_id))
    assert created["AssociationVersion"] == "1", created

    expected_schedule_by_version = {"1": "rate(30 minutes)"}
    for minutes in (40, 50, 60):
        updated = ssm.update_association(
            AssociationId=assoc_id, ScheduleExpression=f"rate({minutes} minutes)"
        )["AssociationDescription"]
        expected_schedule_by_version[updated["AssociationVersion"]] = updated["ScheduleExpression"]
    assert set(expected_schedule_by_version) == {"1", "2", "3", "4"}, expected_schedule_by_version

    page1 = ssm.list_association_versions(AssociationId=assoc_id, MaxResults=2)
    page1_versions = page1["AssociationVersions"]
    assert len(page1_versions) == 2, (
        f"expected exactly 2 items on the first page, got {len(page1_versions)}: {page1_versions!r}"
    )
    next_token = page1.get("NextToken")
    assert next_token, "expected a NextToken on the first page of 2 out of 4 versions"

    page2 = ssm.list_association_versions(
        AssociationId=assoc_id, MaxResults=2, NextToken=next_token
    )
    page2_versions = page2["AssociationVersions"]
    assert len(page2_versions) == 2, (
        f"expected exactly 2 items on the second page, got {len(page2_versions)}: {page2_versions!r}"
    )
    assert not page2.get("NextToken"), (
        f"expected no NextToken once all 4 versions are exhausted, got {page2.get('NextToken')!r}"
    )

    page1_nums = [v["AssociationVersion"] for v in page1_versions]
    page2_nums = [v["AssociationVersion"] for v in page2_versions]
    all_nums = page1_nums + page2_nums
    assert sorted(all_nums) == ["1", "2", "3", "4"], (
        f"the two pages together should cover versions 1-4 exactly once, got {sorted(all_nums)}"
    )

    by_version = {v["AssociationVersion"]: v for v in page1_versions + page2_versions}
    for version, schedule in expected_schedule_by_version.items():
        assert by_version[version]["ScheduleExpression"] == schedule, (
            f"version {version} should carry {schedule!r}, got "
            f"{by_version[version]['ScheduleExpression']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
