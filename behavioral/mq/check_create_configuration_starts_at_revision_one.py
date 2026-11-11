"""create-configuration-starts-at-revision-one."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-configuration-starts-at-revision-one"
GROUP = "state"
SERVICES = ["mq"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created configuration always starts at LatestRevision.Revision == 1."""
    mq = ctx.client("mq")
    name = ctx.unique_name("sim2real-mqcfg-")
    resp = mq.create_configuration(EngineType="ACTIVEMQ", Name=name, Tags={"sim2real": CHECK})
    config_id = resp["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))

    revision = resp["LatestRevision"]["Revision"]
    assert revision == 1, f"expected CreateConfiguration LatestRevision.Revision == 1, got {revision}"
    assert resp["Name"] == name, f"expected CreateConfiguration Name == {name!r}, got {resp['Name']!r}"

    described = mq.describe_configuration(ConfigurationId=config_id)
    described_revision = described["LatestRevision"]["Revision"]
    assert described_revision == 1, (
        f"expected DescribeConfiguration LatestRevision.Revision == 1, got {described_revision}"
    )
    assert described["Name"] == name, f"expected DescribeConfiguration Name == {name!r}, got {described['Name']!r}"
    assert described.get("EngineType", "").upper() == "ACTIVEMQ", described


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
