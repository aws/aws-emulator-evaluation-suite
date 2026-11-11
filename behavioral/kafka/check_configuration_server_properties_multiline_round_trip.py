"""configuration-server-properties-multiline-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-server-properties-multiline-round-trip"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Multi-line server.properties content with tabs, trailing spaces, comments and
    special characters submitted to CreateConfiguration is returned byte-identical
    via DescribeConfigurationRevision.
    """
    kafka = ctx.client("kafka")

    server_properties_text = (
        "# comment with unicode: h\u00e9llo-\u4e16\u754c and a trailing tab\t\n"
        "\n"
        "auto.create.topics.enable=true\n"
        "log.retention.hours=168\n"
        "message.max.bytes=1048588\n"
        "offsets.topic.replication.factor=3\n"
        "min.insync.replicas=2\n"
        "   \n"
        "unclean.leader.election.enable=false\n"
    )
    server_properties_bytes = server_properties_text.encode("utf-8")

    name = ctx.unique_name("sim2real-behav-cfg-")
    resp = kafka.create_configuration(Name=name, ServerProperties=server_properties_bytes)
    arn = resp["Arn"]
    revision = resp["LatestRevision"]["Revision"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn))

    described = kafka.describe_configuration_revision(Arn=arn, Revision=revision)
    returned_bytes = described["ServerProperties"]
    if hasattr(returned_bytes, "read"):
        returned_bytes = returned_bytes.read()
    assert returned_bytes == server_properties_bytes, (
        "DescribeConfigurationRevision did not return the multi-line server.properties "
        "content byte-identically"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
