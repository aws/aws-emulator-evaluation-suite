"""configuration-create-rejected-for-unsupported-kafka-version."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-create-rejected-for-unsupported-kafka-version"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration with an unsupported KafkaVersions entry fails with BadRequestException "Unsupported
    KafkaVersion [<version>]. Valid values: [...]" and creates nothing; a supported version is created ACTIVE."""
    kafka = ctx.client("kafka")
    valid_version = _pick_kafka_version(kafka)

    bad_name = ctx.unique_name("sim2real-msk-cfg-bad-")
    code, message = _error_code(
        lambda: kafka.create_configuration(
            Name=bad_name,
            KafkaVersions=["0.0.1-does-not-exist"],
            ServerProperties=b"auto.create.topics.enable=true\n",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    # The message ends with MSK's whole Kafka version catalogue, which changes whenever MSK releases
    # or retires a version, so only the text before the list and its closing bracket are fixed.
    assert message.startswith("Unsupported KafkaVersion [0.0.1-does-not-exist]. Valid values: [") and (
        message.endswith("]")
    ), message

    # effect absent: nothing with this name was actually persisted
    names = {c["Name"] for c in kafka.list_configurations().get("Configurations", [])}
    assert bad_name not in names, "a configuration with an unsupported KafkaVersions entry was persisted"

    # positive control: the identical call shape with a real, supported version succeeds
    good_name = ctx.unique_name("sim2real-msk-cfg-good-")
    created = kafka.create_configuration(
        Name=good_name,
        KafkaVersions=[valid_version],
        ServerProperties=b"auto.create.topics.enable=true\n",
    )
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=created["Arn"]))
    assert created["Name"] == good_name
    assert created["State"] == "ACTIVE"

    # terminal read: independent of the mutating call, at the destination
    described = kafka.describe_configuration(Arn=created["Arn"])
    assert described["Name"] == good_name, described
    assert described["State"] == "ACTIVE", described
    assert described["LatestRevision"]["Revision"] == 1, described["LatestRevision"]


def _pick_kafka_version(kafka) -> str:
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
