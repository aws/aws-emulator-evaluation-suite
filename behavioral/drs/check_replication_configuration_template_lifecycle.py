"""replication-configuration-template-lifecycle."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-configuration-template-lifecycle"
GROUP = "state"
SERVICES = ["drs"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """Create and Update persist the staging and replication settings, observable through an
    independent Describe read, and delete removes it from that same read.
    """
    drs = ctx.client("drs")
    subnet_id = _any_subnet_id(ctx)

    created = drs.create_replication_configuration_template(
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
        stagingAreaTags={"sim2real-staging": "probe"},
        pitPolicy=[
            {
                "ruleID": 1,
                "units": "MINUTE",
                "interval": 10,
                "retentionDuration": 60,
                "enabled": True,
            },
            {"ruleID": 2, "units": "HOUR", "interval": 1, "retentionDuration": 24, "enabled": True},
            {"ruleID": 3, "units": "DAY", "interval": 1, "retentionDuration": 7, "enabled": True},
        ],
    )
    rct_id = created["replicationConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _delete_rct(drs, rct_id))
    assert created["bandwidthThrottling"] == 0, (
        f"expected bandwidthThrottling=0 on create, got {created['bandwidthThrottling']!r}"
    )
    assert created["ebsEncryption"] == "DEFAULT", (
        f"expected ebsEncryption=DEFAULT on create, got {created['ebsEncryption']!r}"
    )

    updated = drs.update_replication_configuration_template(
        replicationConfigurationTemplateID=rct_id,
        bandwidthThrottling=500,
        ebsEncryption="DEFAULT",
    )
    assert updated["bandwidthThrottling"] == 500, (
        f"expected bandwidthThrottling=500 in update response, got {updated['bandwidthThrottling']!r}"
    )

    described = drs.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[rct_id]
    )["items"][0]
    assert described["bandwidthThrottling"] == 500, (
        f"expected bandwidthThrottling=500 in independent describe read, "
        f"got {described['bandwidthThrottling']!r}"
    )
    assert described["stagingAreaSubnetId"] == subnet_id, (
        f"expected stagingAreaSubnetId={subnet_id!r} to persist, got {described['stagingAreaSubnetId']!r}"
    )
    assert len(described["pitPolicy"]) == 3, (
        f"expected the 3-rule PIT policy to persist exactly, got {described['pitPolicy']!r}"
    )

    drs.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
    remaining = drs.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[rct_id]
    )["items"]
    assert remaining == [], (
        f"the template must be gone from an independent describe read after delete, got {remaining!r}"
    )


def _any_subnet_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in the run's network to run the check")
    return subnets[0]["SubnetId"]


def _delete_rct(drs, rct_id: str) -> None:
    try:
        drs.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
