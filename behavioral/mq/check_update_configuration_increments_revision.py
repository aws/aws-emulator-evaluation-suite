"""update-configuration-increments-revision."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "update-configuration-increments-revision"
GROUP = "state"
SERVICES = ["mq"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfiguration creates a new revision; LatestRevision.Revision increments by 1."""
    mq = ctx.client("mq")
    name = ctx.unique_name("sim2real-mqcfg-")
    created = mq.create_configuration(EngineType="ACTIVEMQ", Name=name, Tags={"sim2real": CHECK})
    config_id = created["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))
    assert created["LatestRevision"]["Revision"] == 1, created["LatestRevision"]

    xml = '<broker xmlns="http://activemq.apache.org/schema/core"><plugins/></broker>'
    data_b64 = base64.b64encode(xml.encode("utf-8")).decode("ascii")
    updated = mq.update_configuration(ConfigurationId=config_id, Data=data_b64)
    assert updated["LatestRevision"]["Revision"] == 2, updated["LatestRevision"]

    described = mq.describe_configuration(ConfigurationId=config_id)
    assert described["LatestRevision"]["Revision"] == 2, described["LatestRevision"]

    revisions = mq.list_configuration_revisions(ConfigurationId=config_id)["Revisions"]
    revision_numbers = sorted(r["Revision"] for r in revisions)
    assert revision_numbers == [1, 2], revision_numbers


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
