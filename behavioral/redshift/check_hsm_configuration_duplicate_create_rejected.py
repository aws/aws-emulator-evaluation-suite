"""hsm-configuration-duplicate-create-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hsm-configuration-duplicate-create-rejected"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHsmConfiguration with an identifier that is already in use is rejected
    with HsmConfigurationAlreadyExistsFault, the original configuration's fields are
    left untouched, and a fresh identifier still succeeds (positive control)."""
    redshift = ctx.client("redshift")

    hsm_id = ctx.unique_name("sim2real-behav-hsm-dup-")
    redshift.create_hsm_configuration(
        HsmConfigurationIdentifier=hsm_id,
        Description="original description",
        HsmIpAddress="203.0.113.9",
        HsmPartitionName="PARTITION1",
        HsmPartitionPassword="Sim2RealHsmPw1!",
        HsmServerPublicCertificate="ZmFrZS1jZXJ0aWZpY2F0ZS1kYXRh",
    )
    ctx.on_cleanup(lambda: redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id))

    code, message = _error(
        lambda: redshift.create_hsm_configuration(
            HsmConfigurationIdentifier=hsm_id,
            Description="a completely different description",
            HsmIpAddress="198.51.100.9",
            HsmPartitionName="PARTITION2",
            HsmPartitionPassword="AnotherPw1!",
            HsmServerPublicCertificate="YW5vdGhlci1mYWtlLWNlcnQ=",
        )
    )
    assert code == "HsmConfigurationAlreadyExistsFault", (
        f"expected HsmConfigurationAlreadyExistsFault for a duplicate identifier, got {code!r}"
    )
    expected_message = (
        "Cannot create the HSM configuration because a configuration with the identifier "
        f"{hsm_id} already exists."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the effect is absent: the original configuration was not overwritten
    listed = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)[
        "HsmConfigurations"
    ]
    assert len(listed) == 1, f"expected exactly one hsm configuration for {hsm_id!r}, got {listed}"
    assert listed[0]["Description"] == "original description", (
        f"rejected duplicate create mutated Description, got {listed[0]['Description']!r}"
    )
    assert listed[0]["HsmIpAddress"] == "203.0.113.9", (
        f"rejected duplicate create mutated HsmIpAddress, got {listed[0]['HsmIpAddress']!r}"
    )
    assert listed[0]["HsmPartitionName"] == "PARTITION1", (
        f"rejected duplicate create mutated HsmPartitionName, got {listed[0]['HsmPartitionName']!r}"
    )

    # positive control (same file): a fresh, unused identifier still succeeds
    other_id = ctx.unique_name("sim2real-behav-hsm-dup2-")
    redshift.create_hsm_configuration(
        HsmConfigurationIdentifier=other_id,
        Description="second config",
        HsmIpAddress="198.51.100.20",
        HsmPartitionName="PARTITION3",
        HsmPartitionPassword="ThirdPw1!",
        HsmServerPublicCertificate="dGhpcmQtZmFrZS1jZXJ0",
    )
    ctx.on_cleanup(lambda: redshift.delete_hsm_configuration(HsmConfigurationIdentifier=other_id))
    other_listed = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=other_id)[
        "HsmConfigurations"
    ]
    assert len(other_listed) == 1, (
        f"expected exactly one hsm configuration for {other_id!r}, got {other_listed}"
    )
    assert other_listed[0]["Description"] == "second config", (
        f"positive control config has wrong Description, got {other_listed[0]['Description']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
