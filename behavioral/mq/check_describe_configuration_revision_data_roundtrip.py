"""describe-configuration-revision-data-roundtrip."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "describe-configuration-revision-data-roundtrip"
GROUP = "state"
SERVICES = ["mq"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The base64 Data written by UpdateConfiguration is retrievable verbatim via DescribeConfigurationRevision."""
    mq = ctx.client("mq")
    name = ctx.unique_name("sim2real-mqcfg-")
    config_id = mq.create_configuration(
        EngineType="ACTIVEMQ", Name=name, Tags={"sim2real": CHECK}
    )["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))

    marker = ctx.unique_name("marker-")
    xml = (
        '<broker xmlns="http://activemq.apache.org/schema/core">'
        f"<!-- {marker} --></broker>"
    )
    data_b64 = base64.b64encode(xml.encode("utf-8")).decode("ascii")
    updated = mq.update_configuration(ConfigurationId=config_id, Data=data_b64)
    revision = updated["LatestRevision"]["Revision"]
    assert revision == 2, f"expected the first update to land as revision 2, got {revision}"

    fetched = mq.describe_configuration_revision(
        ConfigurationId=config_id, ConfigurationRevision=str(revision)
    )
    decoded = base64.b64decode(fetched["Data"]).decode("utf-8")
    assert marker in decoded, f"expected marker {marker!r} in decoded Data, got {decoded!r}"
    assert fetched["ConfigurationId"] == config_id, (
        f"expected ConfigurationId {config_id!r} echoed back, got {fetched['ConfigurationId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
