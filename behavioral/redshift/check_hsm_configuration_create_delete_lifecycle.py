"""hsm-configuration-create-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "hsm-configuration-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHsmConfiguration transitions the resource into existence (visible via
    DescribeHsmConfigurations) and DeleteHsmConfiguration removes it, leaving a
    subsequent describe empty (HsmConfigurationNotFoundFault)."""
    redshift = ctx.client("redshift")
    hsm_id = ctx.unique_name("sim2real-hsmcfg-")

    redshift.create_hsm_configuration(
        HsmConfigurationIdentifier=hsm_id,
        Description="sim2real behavioral test hsm configuration",
        HsmIpAddress="203.0.113.25",
        HsmPartitionName="PARTITION1",
        HsmPartitionPassword="Sim2RealTestPassw0rd1",
        HsmServerPublicCertificate="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VjZXJ0Cg==",
    )
    ctx.on_cleanup(lambda: _delete_hsm_configuration_ignore_missing(ctx, hsm_id))

    # observable creation: visible via describe with the fields we submitted
    described = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)
    configs = described["HsmConfigurations"]
    assert len(configs) == 1, f"expected exactly one hsm configuration, got {configs}"
    cfg = configs[0]
    assert cfg["HsmConfigurationIdentifier"] == hsm_id, (
        f"expected identifier {hsm_id!r}, got {cfg['HsmConfigurationIdentifier']!r}"
    )
    assert cfg["HsmIpAddress"] == "203.0.113.25", f"expected submitted IP, got {cfg['HsmIpAddress']!r}"
    assert cfg["HsmPartitionName"] == "PARTITION1", (
        f"expected submitted partition name, got {cfg['HsmPartitionName']!r}"
    )

    # a second create with the same identifier must be rejected as a conflict, not silently
    # accepted/overwritten -- distinct boundary from the not-found check below
    dup_code, dup_message = _error(
        lambda: redshift.create_hsm_configuration(
            HsmConfigurationIdentifier=hsm_id,
            Description="duplicate attempt",
            HsmIpAddress="203.0.113.26",
            HsmPartitionName="PARTITION2",
            HsmPartitionPassword="Sim2RealTestPassw0rd2",
            HsmServerPublicCertificate="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VjZXJ0Cg==",
        )
    )
    assert dup_code == "HsmConfigurationAlreadyExistsFault", (
        f"expected HsmConfigurationAlreadyExistsFault for duplicate identifier, got {dup_code}"
    )
    expected_dup = (
        "Cannot create the HSM configuration because a configuration with the identifier "
        f"{hsm_id} already exists."
    )
    assert dup_message == expected_dup, f"expected message {expected_dup!r}, got {dup_message!r}"

    # effect absent: the rejected duplicate must not have touched the original configuration
    after_dup = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)[
        "HsmConfigurations"
    ][0]
    assert after_dup["HsmIpAddress"] == "203.0.113.25", (
        f"rejected duplicate create mutated HsmIpAddress, got {after_dup['HsmIpAddress']!r}"
    )
    assert after_dup["HsmPartitionName"] == "PARTITION1", (
        f"rejected duplicate create mutated HsmPartitionName, got {after_dup['HsmPartitionName']!r}"
    )

    redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)

    # terminal state: the resource is fully gone
    code, message = _error(
        lambda: redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)
    )
    assert code == "HsmConfigurationNotFoundFault", (
        f"expected HsmConfigurationNotFoundFault after delete, got {code}"
    )
    expected_describe = f"HSM configuration '{hsm_id}' not found."
    assert message == expected_describe, f"expected message {expected_describe!r}, got {message!r}"

    # a mutation on the dead id also fails, with the same specific not-found code
    second_delete_code, second_delete_message = _error(
        lambda: redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)
    )
    assert second_delete_code == "HsmConfigurationNotFoundFault", (
        f"expected HsmConfigurationNotFoundFault deleting an already-deleted id, got {second_delete_code}"
    )
    expected_delete = f"HSM configuration not found: {hsm_id}"
    assert second_delete_message == expected_delete, (
        f"expected message {expected_delete!r}, got {second_delete_message!r}"
    )

    # the identifier is reusable once fully deleted
    redshift.create_hsm_configuration(
        HsmConfigurationIdentifier=hsm_id,
        Description="sim2real behavioral test hsm configuration reused",
        HsmIpAddress="203.0.113.27",
        HsmPartitionName="PARTITION3",
        HsmPartitionPassword="Sim2RealTestPassw0rd3",
        HsmServerPublicCertificate="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmZha2VjZXJ0Cg==",
    )
    reused = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)[
        "HsmConfigurations"
    ][0]
    assert reused["HsmPartitionName"] == "PARTITION3", (
        f"expected the reused identifier to hold the new config, got {reused['HsmPartitionName']!r}"
    )
    redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_hsm_configuration_ignore_missing(ctx, hsm_id):
    from botocore.exceptions import ClientError

    redshift = ctx.client("redshift")
    try:
        redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "HsmConfigurationNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
