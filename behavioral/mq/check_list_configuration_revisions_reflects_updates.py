"""list-configuration-revisions-reflects-updates."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "list-configuration-revisions-reflects-updates"
GROUP = "state"
SERVICES = ["mq"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConfigurationRevisions grows by exactly one entry per UpdateConfiguration call."""
    mq = ctx.client("mq")
    name = ctx.unique_name("sim2real-mqcfg-")
    config_id = mq.create_configuration(EngineType="ACTIVEMQ", Name=name, Tags={"sim2real": CHECK})["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))

    for i in range(2):
        xml = f'<broker xmlns="http://activemq.apache.org/schema/core"><!-- rev-{i} --></broker>'
        data_b64 = base64.b64encode(xml.encode("utf-8")).decode("ascii")
        mq.update_configuration(ConfigurationId=config_id, Data=data_b64)

    revisions = mq.list_configuration_revisions(ConfigurationId=config_id)["Revisions"]
    revision_numbers = sorted(r["Revision"] for r in revisions)
    assert revision_numbers == [1, 2, 3], revision_numbers

    final = mq.describe_configuration(ConfigurationId=config_id)
    assert final["LatestRevision"]["Revision"] == 3, final["LatestRevision"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
