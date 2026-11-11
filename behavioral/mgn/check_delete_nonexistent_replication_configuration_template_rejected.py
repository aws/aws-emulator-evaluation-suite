"""delete-nonexistent-replication-configuration-template-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-replication-configuration-template-rejected"
GROUP = "overly-permissive"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteReplicationConfigurationTemplate on an id never created fails with
    ResourceNotFoundException, while deleting a template the check created succeeds.
    """
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
        stagingAreaTags={"SimParityCheck": CHECK},
    )
    real_id = created["replicationConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _safe_delete(mgn, real_id))

    mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=real_id)
    remaining = mgn.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[real_id]
    )["items"]
    assert remaining == [], (
        f"positive control: deleting a real replicationConfigurationTemplateID must remove "
        f"it, DescribeReplicationConfigurationTemplates still returned {remaining!r}"
    )

    fake_id = "rct-" + "0" * 17
    code, message = None, None
    try:
        mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=fake_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "ResourceNotFoundException", (
        f"deleting a nonexistent replicationConfigurationTemplateID must raise "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = f"Replication Configuration Template with Id: '{fake_id}' was not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _safe_delete(mgn, rct_id) -> None:
    try:
        mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
