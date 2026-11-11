"""hsm-configuration-duplicate-identifier-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "hsm-configuration-duplicate-identifier-rejected"
GROUP = "representation"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHsmConfiguration with an existing identifier is HsmConfigurationAlreadyExistsFault, and
    the original configuration is left unchanged.
    """
    rs = ctx.client("redshift")
    hsm_id = ctx.unique_name("sim2real-hsmdup-").lower().replace("_", "-")
    original_description = "original-config-do-not-overwrite"

    rs.create_hsm_configuration(
        HsmConfigurationIdentifier=hsm_id,
        Description=original_description,
        HsmIpAddress="203.0.113.9",
        HsmPartitionName="original-partition",
        HsmPartitionPassword="Passw0rd!Orig1",
        HsmServerPublicCertificate="ORIGINAL-CERT-BODY",
        Tags=[{"Key": "sim2real-audit", "Value": hsm_id}],
    )
    ctx.on_cleanup(lambda: _delete_hsm_configuration(rs, hsm_id))

    # Positive control: the configuration we just created is describable.
    described = rs.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)["HsmConfigurations"][0]
    assert described["Description"] == original_description

    code, message = _error(
        lambda: rs.create_hsm_configuration(
            HsmConfigurationIdentifier=hsm_id,
            Description="attempted-overwrite-should-not-stick",
            HsmIpAddress="203.0.113.10",
            HsmPartitionName="attacker-partition",
            HsmPartitionPassword="Passw0rd!Evil2",
            HsmServerPublicCertificate="EVIL-CERT-BODY",
        )
    )
    assert code == "HsmConfigurationAlreadyExistsFault", f"expected duplicate rejection, got {code!r}"
    expected_message = (
        "Cannot create the HSM configuration because a configuration with the identifier "
        f"{hsm_id} already exists."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the original configuration is unchanged by the rejected call. There is
    # no delete-then-recreate leg: recreating a just-deleted identifier returns InternalFailure
    # for minutes.
    after = rs.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)["HsmConfigurations"][0]
    assert after["Description"] == original_description, "rejected duplicate create mutated the original config"
    assert after["HsmPartitionName"] == "original-partition"



def _error(fn):
    """Call fn(); return (code, message) of its ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError rejection but the call succeeded: {result!r}")


def _delete_hsm_configuration(rs: Any, hsm_id: str) -> None:
    try:
        rs.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "HsmConfigurationNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
