"""create-configuration-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-invalid-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["mq"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration rejects a Name outside the allowed charset (space/'!') with BadRequestException."""
    mq = ctx.client("mq")
    invalid_name = ctx.unique_name("sim2real mqcfg!")

    code, message = _error(lambda: mq.create_configuration(EngineType="ACTIVEMQ", Name=invalid_name))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Make sure your Configuration name only contains valid characters.", message

    # effect absent: nothing was created under that name.
    matches = [c for c in mq.list_configurations()["Configurations"] if c["Name"] == invalid_name]
    assert matches == [], f"expected no configuration named {invalid_name!r}, found {matches}"

    # positive control: a valid name succeeds.
    valid_name = ctx.unique_name("sim2real-mqcfg-valid-")
    created = mq.create_configuration(EngineType="ACTIVEMQ", Name=valid_name, Tags={"sim2real": "audit"})
    config_id = created["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))
    assert created["Name"] == valid_name, f"expected created Name {valid_name!r}, got {created['Name']!r}"

    # terminal read: independent of the mutating CreateConfiguration call, at the destination.
    described = mq.describe_configuration(ConfigurationId=config_id)
    assert described["Name"] == valid_name, (
        f"expected DescribeConfiguration Name {valid_name!r}, got {described.get('Name')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
