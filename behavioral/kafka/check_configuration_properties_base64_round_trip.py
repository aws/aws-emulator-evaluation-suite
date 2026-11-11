"""configuration-properties-base64-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-properties-base64-round-trip"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationRevision returns exactly the ServerProperties bytes passed to
    CreateConfiguration, including comments, blank lines and trailing whitespace."""
    kafka = ctx.client("kafka")
    kafka_version = _pick_kafka_version(kafka)
    server_properties = (
        b"auto.create.topics.enable=true\n"
        b"default.replication.factor=3\n"
        b"min.insync.replicas=2\n"
        b"# a trailing-whitespace comment line   \n"
        b"\n"
        b"   \n"
    )
    name = ctx.unique_name("sim2real-msk-cfg-")
    created = kafka.create_configuration(
        Name=name,
        Description="sim2real base64 round-trip check",
        KafkaVersions=[kafka_version],
        ServerProperties=server_properties,
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn))
    revision = created["LatestRevision"]["Revision"]

    described = kafka.describe_configuration_revision(Arn=arn, Revision=revision)
    returned = described["ServerProperties"]
    if isinstance(returned, str):
        returned = returned.encode("utf-8")
    assert returned == server_properties, (
        f"server properties not byte-identical: sent {server_properties!r}, got {returned!r}"
    )


def _pick_kafka_version(kafka) -> str:
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
