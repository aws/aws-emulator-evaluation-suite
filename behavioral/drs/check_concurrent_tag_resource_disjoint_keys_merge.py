"""concurrent-tag-resource-disjoint-keys-merge."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-disjoint-keys-merge"
GROUP = "tagging"
SERVICES = ["drs", "ec2"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on the resource's own
    not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _az(ec2) -> str:
    """An AZ this region currently offers, derived rather than hardcoded."""
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    assert zones, "no available AZ in this region"
    return zones[0]["ZoneName"]


@tags(
    "requires:drs-initialized",
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Two TagResource calls on the same Replication Configuration Template, each adding a
    different tag key, both land: a concurrent write to one key never drops the other's."""
    ec2 = ctx.client("ec2")
    drs = ctx.client("drs")

    vpc_id = ec2.create_vpc(CidrBlock="10.233.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.233.1.0/24", AvailabilityZone=_az(ec2)
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound")
    )
    sg_name = ctx.unique_name("sim2real-behav-drs-")
    sg_id = ec2.create_security_group(GroupName=sg_name, Description=sg_name, VpcId=vpc_id)[
        "GroupId"
    ]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_security_group(GroupId=sg_id), "InvalidGroup.NotFound")
    )

    created = drs.create_replication_configuration_template(
        stagingAreaSubnetId=subnet_id,
        replicationServersSecurityGroupsIDs=[sg_id],
        ebsEncryption="DEFAULT",
        bandwidthThrottling=0,
        stagingAreaTags={},
        pitPolicy=[
            {
                "ruleID": 1,
                "units": "MINUTE",
                "interval": 10,
                "retentionDuration": 60,
                "enabled": True,
            },
            {"ruleID": 2, "units": "HOUR", "interval": 1, "retentionDuration": 24, "enabled": True},
            {"ruleID": 3, "units": "DAY", "interval": 1, "retentionDuration": 14, "enabled": True},
        ],
        associateDefaultSecurityGroup=False,
        createPublicIP=False,
        dataPlaneRouting="PRIVATE_IP",
        defaultLargeStagingDiskType="GP3",
        replicationServerInstanceType="t3.small",
        useDedicatedReplicationServer=False,
    )
    template_id = created["replicationConfigurationTemplateID"]
    template_arn = created["arn"]
    ctx.on_cleanup(
        _teardown(
            lambda: drs.delete_replication_configuration_template(
                replicationConfigurationTemplateID=template_id
            ),
            "ResourceNotFoundException",
        )
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(drs.tag_resource, resourceArn=template_arn, tags={"first": "one"}),
            pool.submit(drs.tag_resource, resourceArn=template_arn, tags={"second": "two"}),
        ]
        for f in futures:
            f.result()

    tags_after = drs.list_tags_for_resource(resourceArn=template_arn)["tags"]
    assert tags_after.get("first") == "one", (
        f"'first' tag missing or wrong after concurrent writes: {tags_after!r}"
    )
    assert tags_after.get("second") == "two", (
        f"'second' tag missing or wrong after concurrent writes: {tags_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
