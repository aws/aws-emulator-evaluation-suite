"""configuration-server-properties-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-server-properties-round-trip"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The server-properties blob supplied at CreateConfiguration is retrievable
    byte-for-byte via DescribeConfigurationRevision -- no re-serialization,
    reordering, or trimming of the raw broker-config content."""
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-kafka-cfg-")
    server_properties = (
        b"auto.create.topics.enable=true\n"
        b"default.replication.factor=2\n"
        b"min.insync.replicas=1\n"
        b"num.io.threads=8\n"
        b"log.retention.hours=48\n"
    )
    created = kafka.create_configuration(Name=name, ServerProperties=server_properties)
    arn = created["Arn"]
    revision = created["LatestRevision"]["Revision"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn))

    fetched = kafka.describe_configuration_revision(Arn=arn, Revision=revision)
    fetched_bytes = _as_bytes(fetched["ServerProperties"])
    assert fetched_bytes == server_properties, (
        f"server properties not byte-identical: sent {server_properties!r}, got {fetched_bytes!r}"
    )


def _as_bytes(value):
    if hasattr(value, "read"):
        return value.read()
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
