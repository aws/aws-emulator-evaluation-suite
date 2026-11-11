"""configuration-unicode-properties-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-unicode-properties-round-trip"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode/comment/multi-line ServerProperties content survives byte-identical through
    DescribeConfigurationRevision after CreateConfiguration."""
    kafka = ctx.client("kafka")
    raw_properties = (
        "# Amazon MSK custom configuration \u2014 sim2real round-trip check\n"
        "# Unicode comment: caf\u00e9, na\u00efve, Z\u00fcrich, \u6d4b\u8bd5\n"
        "\n"
        "auto.create.topics.enable=true\n"
        "default.replication.factor=3\n"
        "log.retention.ms=300000\n"
        "min.insync.replicas=2\n"
    ).encode("utf-8")

    name = ctx.unique_name("sim2real-msk-cfg-")
    created = kafka.create_configuration(Name=name, ServerProperties=raw_properties)
    arn = created["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn))

    assert created["Name"] == name, (
        f"CreateConfiguration echoed Name={created['Name']!r}, expected {name!r}"
    )
    assert created["LatestRevision"]["Revision"] == 1, (
        f"a fresh CreateConfiguration must mint revision 1, got "
        f"{created['LatestRevision']['Revision']!r}"
    )

    revision = kafka.describe_configuration_revision(Arn=arn, Revision=1)
    fetched_bytes = _as_bytes(revision["ServerProperties"])

    assert fetched_bytes == raw_properties, (
        "ServerProperties bytes changed across the CreateConfiguration -> DescribeConfigurationRevision "
        "round trip; unicode/comment/line-continuation content must be preserved verbatim"
    )


def _as_bytes(blob):
    return blob.read() if hasattr(blob, "read") else blob


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
