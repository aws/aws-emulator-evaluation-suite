"""create-replication-configuration-template-nonexistent-subnet-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-replication-configuration-template-nonexistent-subnet-rejected"
GROUP = "overly-permissive"
SERVICES = ["drs"]

_BASE_KWARGS = dict(
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
    pitPolicy=[
        {"ruleID": 1, "units": "MINUTE", "interval": 10, "retentionDuration": 60, "enabled": True},
        {"ruleID": 2, "units": "HOUR", "interval": 1, "retentionDuration": 24, "enabled": True},
        {"ruleID": 3, "units": "DAY", "interval": 1, "retentionDuration": 7, "enabled": True},
    ],
)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """CreateReplicationConfigurationTemplate refuses a well-formed but nonexistent subnet id
    with ValidationException naming that subnet, and creates nothing, while the identical
    request against a real subnet succeeds.
    """
    drs = ctx.client("drs")
    fake_subnet = "subnet-00000000deadbeef0"

    code, message = _expect_rejected(
        lambda: drs.create_replication_configuration_template(
            stagingAreaSubnetId=fake_subnet, **_BASE_KWARGS
        )
    )
    assert code == "ValidationException", (
        f"CreateReplicationConfigurationTemplate with a nonexistent subnet got {code!r}"
    )
    assert message == f"SubnetId {fake_subnet} wasn't found", (
        f"expected the exact subnet-not-found message, got {message!r}"
    )

    # Positive control: the identical request against a real subnet succeeds.
    real_subnet = _any_subnet_id(ctx)
    created = drs.create_replication_configuration_template(
        stagingAreaSubnetId=real_subnet, **_BASE_KWARGS
    )
    rct_id = created["replicationConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _delete_rct(drs, rct_id))
    assert created["stagingAreaSubnetId"] == real_subnet, (
        f"expected the real subnet to be accepted, got {created.get('stagingAreaSubnetId')!r}"
    )


def _any_subnet_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in the run's network to run the check")
    return subnets[0]["SubnetId"]


def _expect_rejected(fn):
    try:
        result = fn()
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")


def _delete_rct(drs, rct_id: str) -> None:
    try:
        drs.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
