"""hsm-configuration-duplicate-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "hsm-configuration-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHsmConfiguration with an existing name is rejected with HsmConfigurationAlreadyExistsFault
    and its exact message, leaving the original unchanged; a distinct name succeeds, and the name
    is reusable once the original is deleted."""
    redshift = ctx.client("redshift")
    name = ctx.unique_name("sim2real-hsmcfg-")
    other_name = ctx.unique_name("sim2real-hsmcfg2-")

    def _create(ident, description):
        return redshift.create_hsm_configuration(
            HsmConfigurationIdentifier=ident,
            Description=description,
            HsmIpAddress="10.0.0.10",
            HsmPartitionName="partition1",
            HsmPartitionPassword="Sim2RealTestPassword123",
            HsmServerPublicCertificate="-----BEGIN CERTIFICATE-----\nZmFrZS1jZXJ0\n-----END CERTIFICATE-----",
        )

    def _delete_idempotent(ident):
        from botocore.exceptions import ClientError

        try:
            redshift.delete_hsm_configuration(HsmConfigurationIdentifier=ident)
        except ClientError as err:
            if err.response["Error"]["Code"] != "HsmConfigurationNotFoundFault":
                raise

    _create(name, "original description")
    ctx.on_cleanup(lambda: _delete_idempotent(name))

    code, message = _error(lambda: _create(name, "duplicate attempt description"))
    assert code == "HsmConfigurationAlreadyExistsFault", (
        f"expected HsmConfigurationAlreadyExistsFault on duplicate identifier, got {code!r}"
    )
    expected_message = (
        "Cannot create the HSM configuration because a configuration with the identifier "
        f"{name} already exists."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original configuration is untouched by the rejected duplicate attempt.
    described = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=name)
    configs = described["HsmConfigurations"]
    assert len(configs) == 1, f"expected exactly 1 config for {name!r}, got {len(configs)}"
    assert configs[0]["Description"] == "original description", (
        f"expected original description preserved, got {configs[0]['Description']!r}"
    )

    # positive control: creating a distinctly-named configuration still works.
    _create(other_name, "control description")
    ctx.on_cleanup(lambda: _delete_idempotent(other_name))
    control = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=other_name)
    assert control["HsmConfigurations"][0]["Description"] == "control description", (
        f"expected control description, got {control['HsmConfigurations'][0]['Description']!r}"
    )

    # restore: freeing the identifier by deleting the original makes the identical
    # identifier -- rejected moments ago -- available again.
    redshift.delete_hsm_configuration(HsmConfigurationIdentifier=name)
    gone_code, gone_message = _error(
        lambda: redshift.describe_hsm_configurations(HsmConfigurationIdentifier=name)
    )
    assert gone_code == "HsmConfigurationNotFoundFault", (
        f"expected HsmConfigurationNotFoundFault after deleting the original, got {gone_code!r}"
    )
    expected_gone = f"HSM configuration '{name}' not found."
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    _create(name, "recreated after freeing identifier")
    recreated = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=name)
    assert recreated["HsmConfigurations"][0]["Description"] == "recreated after freeing identifier", (
        "expected the freed identifier to be reusable, got "
        f"{recreated['HsmConfigurations'][0]['Description']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
