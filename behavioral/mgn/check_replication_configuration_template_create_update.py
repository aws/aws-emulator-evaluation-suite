"""replication-configuration-template-create-update."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-configuration-template-create-update"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReplicationConfigurationTemplate persists the replication settings, and
    UpdateReplicationConfigurationTemplate changes them in place, both observable through
    DescribeReplicationConfigurationTemplates."""
    mgn = ctx.client("mgn")
    _ensure_initialized(mgn)
    subnet_id = _any_subnet_id(ctx)

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
        lambda: mgn.delete_replication_configuration_template(
            replicationConfigurationTemplateID=rct_id
        )
    )
    assert created["dataPlaneRouting"] == "PRIVATE_IP", (
        f"expected dataPlaneRouting=PRIVATE_IP on create, got {created['dataPlaneRouting']!r}"
    )
    assert created["bandwidthThrottling"] == 0, (
        f"expected bandwidthThrottling=0 on create, got {created['bandwidthThrottling']!r}"
    )

    updated = mgn.update_replication_configuration_template(
        replicationConfigurationTemplateID=rct_id,
        bandwidthThrottling=500,
        ebsEncryption="CUSTOM",
        ebsEncryptionKeyArn=_default_kms_key_arn(ctx),
    )
    assert updated["bandwidthThrottling"] == 500, (
        f"expected bandwidthThrottling=500 in update response, got {updated['bandwidthThrottling']!r}"
    )
    assert updated["ebsEncryption"] == "CUSTOM", (
        f"expected ebsEncryption=CUSTOM in update response, got {updated['ebsEncryption']!r}"
    )

    described = mgn.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[rct_id]
    )["items"][0]
    assert described["bandwidthThrottling"] == 500, (
        f"expected bandwidthThrottling=500 in independent describe read, got {described['bandwidthThrottling']!r}"
    )
    assert described["ebsEncryption"] == "CUSTOM", (
        f"expected ebsEncryption=CUSTOM in independent describe read, got {described['ebsEncryption']!r}"
    )


def _ensure_initialized(mgn) -> None:
    try:
        mgn.initialize_service()
    except ClientError:
        pass


def _any_subnet_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(MaxResults=5, Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in this account/region to run the check")
    return subnets[0]["SubnetId"]


def _default_kms_key_arn(ctx) -> str:
    kms = ctx.client("kms")
    resp = kms.describe_key(KeyId="alias/aws/ebs")
    return resp["KeyMetadata"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
