"""hsm-configuration-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hsm-configuration-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating an HsmConfiguration with an identifier that already exists is rejected
    with HsmConfigurationAlreadyExistsFault, not silently accepted or overwritten."""
    redshift = ctx.client("redshift")
    hsm_id = ctx.unique_name("sim2real-hsmcfg-")

    original = redshift.create_hsm_configuration(
        HsmConfigurationIdentifier=hsm_id,
        Description="sim2real original description",
        HsmIpAddress="10.0.0.10",
        HsmPartitionName="partition-original",
        HsmPartitionPassword="OriginalPassw0rd!23",
        HsmServerPublicCertificate="ORIGINAL-CERT-BODY",
    )["HsmConfiguration"]
    ctx.on_cleanup(lambda: redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id))
    assert original["HsmConfigurationIdentifier"] == hsm_id, (
        f"expected create response to echo {hsm_id!r}, got {original!r}"
    )

    code, message = _error(
        lambda: redshift.create_hsm_configuration(
            HsmConfigurationIdentifier=hsm_id,
            Description="sim2real duplicate description",
            HsmIpAddress="10.0.0.20",
            HsmPartitionName="partition-duplicate",
            HsmPartitionPassword="DuplicatePassw0rd!23",
            HsmServerPublicCertificate="DUPLICATE-CERT-BODY",
        )
    )
    assert code == "HsmConfigurationAlreadyExistsFault", (
        f"expected HsmConfigurationAlreadyExistsFault on duplicate create, got {code!r}"
    )
    expected_message = (
        "Cannot create the HSM configuration because a configuration with the identifier "
        f"{hsm_id} already exists."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected duplicate call must not have mutated the existing config.
    current = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)[
        "HsmConfigurations"
    ][0]
    assert current["Description"] == "sim2real original description", (
        f"rejected duplicate create mutated Description, got {current['Description']!r}"
    )
    assert current["HsmIpAddress"] == "10.0.0.10", (
        f"rejected duplicate create mutated HsmIpAddress, got {current['HsmIpAddress']!r}"
    )
    assert current["HsmPartitionName"] == "partition-original", (
        f"rejected duplicate create mutated HsmPartitionName, got {current['HsmPartitionName']!r}"
    )

    # Positive control: creating a config with a fresh, unused identifier still succeeds.
    other_id = ctx.unique_name("sim2real-hsmcfg-ctrl-")
    control = redshift.create_hsm_configuration(
        HsmConfigurationIdentifier=other_id,
        Description="sim2real control description",
        HsmIpAddress="10.0.0.30",
        HsmPartitionName="partition-control",
        HsmPartitionPassword="ControlPassw0rd!23",
        HsmServerPublicCertificate="CONTROL-CERT-BODY",
    )["HsmConfiguration"]
    ctx.on_cleanup(lambda: redshift.delete_hsm_configuration(HsmConfigurationIdentifier=other_id))
    assert control["HsmConfigurationIdentifier"] == other_id, (
        f"expected create response to echo {other_id!r}, got {control!r}"
    )

    # Independent read at the destination: the control configuration is genuinely persisted, not
    # merely echoed back by the create call that made it.
    control_current = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=other_id)[
        "HsmConfigurations"
    ][0]
    assert control_current["HsmConfigurationIdentifier"] == other_id, (
        f"control config not visible via independent describe, got {control_current!r}"
    )
    assert control_current["Description"] == "sim2real control description", (
        f"expected control Description to persist, got {control_current['Description']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
