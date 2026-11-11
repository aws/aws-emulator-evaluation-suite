"""hsm-configuration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hsm-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created HSM configuration round-trips via DescribeHsmConfigurations; after delete, both a
    read and a second delete fail with HsmConfigurationNotFoundFault and the exact messages."""
    redshift = ctx.client("redshift")

    hsm_id = ctx.unique_name("sim2real-behav-hsm-")
    redshift.create_hsm_configuration(
        HsmConfigurationIdentifier=hsm_id,
        Description="sim2real behavioral hsm config",
        HsmIpAddress="203.0.113.5",
        HsmPartitionName="PARTITION1",
        HsmPartitionPassword="Sim2RealHsmPw1!",
        HsmServerPublicCertificate="ZmFrZS1jZXJ0aWZpY2F0ZS1kYXRh",
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    cleaned_up = {"done": False}

    def _cleanup():
        if not cleaned_up["done"]:
            redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)

    ctx.on_cleanup(_cleanup)

    listed = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)[
        "HsmConfigurations"
    ]
    assert len(listed) == 1, f"expected exactly one hsm configuration for {hsm_id}, got {listed}"
    assert listed[0]["HsmConfigurationIdentifier"] == hsm_id, (
        f"expected identifier {hsm_id}, got {listed[0].get('HsmConfigurationIdentifier')!r}"
    )
    assert listed[0]["Description"] == "sim2real behavioral hsm config", (
        f"expected description to round-trip, got {listed[0].get('Description')!r}"
    )
    assert listed[0]["HsmIpAddress"] == "203.0.113.5", (
        f"expected HsmIpAddress to round-trip, got {listed[0].get('HsmIpAddress')!r}"
    )
    assert listed[0]["HsmPartitionName"] == "PARTITION1", (
        f"expected HsmPartitionName to round-trip, got {listed[0].get('HsmPartitionName')!r}"
    )

    redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)
    cleaned_up["done"] = True

    code, message = _error(
        lambda: redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)
    )
    assert code == "HsmConfigurationNotFoundFault", (
        f"expected HsmConfigurationNotFoundFault for a deleted hsm configuration, got {code!r}"
    )
    expected = f"HSM configuration '{hsm_id}' not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    second_delete_code, second_delete_message = _error(
        lambda: redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)
    )
    assert second_delete_code == "HsmConfigurationNotFoundFault", (
        "expected a delete of an already-deleted hsm configuration to fail with "
        f"HsmConfigurationNotFoundFault, got {second_delete_code!r}"
    )
    expected = f"HSM configuration not found: {hsm_id}"
    assert second_delete_message == expected, (
        f"expected message {expected!r}, got {second_delete_message!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
