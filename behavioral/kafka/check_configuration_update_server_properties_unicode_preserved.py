"""configuration-update-server-properties-unicode-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-update-server-properties-unicode-preserved"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode characters embedded in server-properties content supplied via
    UpdateConfiguration survive a DescribeConfigurationRevision round trip on
    the new revision unchanged, byte-for-byte."""
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-kafka-cfg-")
    initial_properties = b"auto.create.topics.enable=true\n"
    created = kafka.create_configuration(Name=name, ServerProperties=initial_properties)
    arn = created["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn))

    unicode_properties = (
        "# \u00e9\u00e9\u00e9 configuration \u2014 \u65e5\u672c\u8a9e \u2615 caf\u00e9\n"
        "auto.create.topics.enable=true\n"
        "compression.type=producer\n"
    ).encode("utf-8")
    updated = kafka.update_configuration(Arn=arn, ServerProperties=unicode_properties)
    new_revision = updated["LatestRevision"]["Revision"]
    assert new_revision == 2, f"expected UpdateConfiguration to create revision 2, got {new_revision}"

    fetched = kafka.describe_configuration_revision(Arn=arn, Revision=new_revision)
    fetched_bytes = _as_bytes(fetched["ServerProperties"])
    assert fetched_bytes == unicode_properties, (
        f"DescribeConfigurationRevision bytes diverged from what UpdateConfiguration wrote: "
        f"expected {unicode_properties!r}, got {fetched_bytes!r}"
    )
    assert fetched_bytes.decode("utf-8") == unicode_properties.decode("utf-8"), (
        "ServerProperties decoded to different unicode text despite equal bytes"
    )

    # The original revision must remain untouched by the update.
    original = kafka.describe_configuration_revision(Arn=arn, Revision=1)
    original_bytes = _as_bytes(original["ServerProperties"])
    assert original_bytes == initial_properties, (
        f"revision 1 ServerProperties changed after updating to revision 2: "
        f"expected {initial_properties!r}, got {original_bytes!r}"
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
