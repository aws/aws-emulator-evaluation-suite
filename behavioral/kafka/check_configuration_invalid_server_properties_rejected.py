"""configuration-invalid-server-properties-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-invalid-server-properties-rejected"
GROUP = "server-side"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration with ServerProperties that are not a valid Java properties document fails with
    BadRequestException and the per-property message and creates nothing, while the same request with valid
    properties returns ACTIVE."""
    kafka = ctx.client("kafka")

    bad_name = ctx.unique_name("sim2real-kafka-cfg-bad-")
    bad_props = b"this line has no equals sign and is not valid java properties syntax"
    code, message = _error_code(
        lambda: kafka.create_configuration(Name=bad_name, ServerProperties=bad_props)
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for malformed ServerProperties, got {code!r}"
    )
    # MSK reads the line up to its first space as a key; the message ends with the list of Kafka
    # versions it checked that key against, which changes as versions come and go.
    assert message.startswith(
        '[ {\n  "name" : "this",\n  "value" : "line has no equals sign and is not valid java properties '
        'syntax",\n  "errorMessages" : [ "Key \'this\' is not supported by at least one Apache Kafka '
        "version. Key checked against versions: ["
    ) and message.endswith(']" ]\n} ]'), message
    # The effect must be absent: no configuration with that name was actually created.
    listing = kafka.list_configurations().get("Configurations", [])
    assert not any(c["Name"] == bad_name for c in listing), (
        "a configuration was created despite CreateConfiguration returning BadRequestException"
    )

    # Positive control: the identical operation with valid ServerProperties succeeds.
    good_name = ctx.unique_name("sim2real-kafka-cfg-good-")
    good_props = b"auto.create.topics.enable=true\n"
    created = kafka.create_configuration(Name=good_name, ServerProperties=good_props)
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=created["Arn"]))
    assert created["Name"] == good_name, f"expected Name {good_name!r}, got {created['Name']!r}"
    assert created["State"] == "ACTIVE", f"valid configuration was not created ACTIVE: {created['State']}"

    described = kafka.describe_configuration(Arn=created["Arn"])
    assert described["Name"] == good_name, f"expected Name {good_name!r}, got {described['Name']!r}"
    assert described["State"] == "ACTIVE", f"expected State ACTIVE, got {described['State']!r}"


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected CreateConfiguration to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
