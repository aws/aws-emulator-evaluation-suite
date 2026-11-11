"""concurrent-idempotent-delete-replication-configuration-template."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-idempotent-delete-replication-configuration-template"
GROUP = "concurrency"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two racing DeleteReplicationConfigurationTemplate calls either both succeed or one succeeds and
    the other gets ResourceNotFoundException; no other code appears, and the template is gone after.
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
    )
    rct_id = created["replicationConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _safe_delete(mgn, rct_id))

    loser_messages = []

    def _delete(_):
        try:
            mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
            return "ok"
        except ClientError as e:
            loser_messages.append(e.response["Error"].get("Message"))
            return e.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(_delete, range(2)))

    assert outcomes.count("ok") >= 1, f"at least one concurrent delete must succeed, got {outcomes}"
    assert set(outcomes) <= {"ok", "ResourceNotFoundException"}, (
        f"a concurrent delete race must resolve to either both succeeding (idempotent delete) "
        f"or the loser seeing ResourceNotFoundException -- never any other error, got {outcomes}"
    )
    not_found = f"Replication Configuration Template with Id: '{rct_id}' was not found"
    assert all(m == not_found for m in loser_messages), (
        f"a losing concurrent delete must answer {not_found!r}, got {loser_messages!r}"
    )

    # A describe-by-id of a deleted template answers an empty list, not an error.
    remaining = mgn.describe_replication_configuration_templates(
        replicationConfigurationTemplateIDs=[rct_id]
    )["items"]
    assert remaining == [], f"the template must be gone after the race resolves, got {remaining!r}"


def _ensure_initialized(mgn) -> None:
    try:
        mgn.initialize_service()
    except ClientError:
        pass


def _safe_delete(mgn, rct_id: str) -> None:
    try:
        mgn.delete_replication_configuration_template(replicationConfigurationTemplateID=rct_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
