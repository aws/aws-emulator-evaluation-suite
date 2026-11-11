"""replication-configuration-template-filter-excludes-nonmatching."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-configuration-template-filter-excludes-nonmatching"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeReplicationConfigurationTemplates filtered by a created template's id returns exactly
    that id, and filtered by that id plus a nonexistent id returns only the real one.
    """
    mgn = ctx.client("mgn")
    ec2 = ctx.client("ec2")
    _ensure_initialized(mgn)
    subnets = ec2.describe_subnets(MaxResults=5, Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in this account/region to run the check")
    subnet_id = subnets[0]["SubnetId"]

    created = mgn.create_replication_configuration_template(
        stagingAreaSubnetId=subnet_id,
        associateDefaultSecurityGroup=True,
        replicationServersSecurityGroupsIDs=[],
        replicationServerInstanceType="t3.small",
        useDedicatedReplicationServer=False,
        defaultLargeStagingDiskType="GP3",
        ebsEncryption="DEFAULT",
        bandwidthThrottling=0,
        dataPlaneRouting="PRIVATE_IP",
        createPublicIP=False,
        stagingAreaTags={},
        tags={"sim2real-key": "sim2real-value"},
    )
    rct_id = created["replicationConfigurationTemplateID"]
    ctx.on_cleanup(
        lambda: mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
    )

    matching = mgn.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[rct_id]
    )["items"]
    matching_ids = {i["replicationConfigurationTemplateID"] for i in matching}
    assert matching_ids == {rct_id}, (
        f"filtering by [real id] must return exactly that id, expected {{{rct_id!r}}}, got {matching_ids}"
    )

    fake_id = "rct-" + "1" * 17
    mixed = mgn.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[rct_id, fake_id]
    )["items"]
    seen_ids = {i["replicationConfigurationTemplateID"] for i in mixed}
    assert seen_ids == {rct_id}, (
        f"filtering by [real id, nonexistent id] must return only the real one, got {seen_ids}"
    )


def _ensure_initialized(mgn) -> None:
    try:
        mgn.initialize_service()
    except ClientError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
