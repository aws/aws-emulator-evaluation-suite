"""replication-configuration-template-delete-removes-from-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-configuration-template-delete-removes-from-list"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteReplicationConfigurationTemplate, a describe-by-id lookup returns an
    empty list (not a ResourceNotFoundException) and a repeat delete of the same id
    raises ResourceNotFoundException."""
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
    )
    rct_id = created["replicationConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _delete_if_present(mgn, rct_id))

    present = mgn.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[rct_id]
    )["items"]
    assert len(present) == 1, f"expected exactly the created template in describe-by-id, got {present!r}"

    mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)

    remaining = mgn.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[rct_id]
    )["items"]
    assert remaining == [], (
        f"deleted template must not appear in a describe-by-id lookup, got {remaining!r}"
    )

    try:
        mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
        raise AssertionError(
            "deleting an already-deleted template must raise ResourceNotFoundException"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from a repeat delete of a deleted "
            f"template, got {code!r}"
        )
        expected = f"Replication Configuration Template with Id: '{rct_id}' was not found"
        assert message == expected, f"expected message {expected!r}, got {message!r}"


def _ensure_initialized(mgn) -> None:
    try:
        mgn.initialize_service()
    except ClientError:
        pass


def _delete_if_present(mgn, rct_id: str) -> None:
    try:
        mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
