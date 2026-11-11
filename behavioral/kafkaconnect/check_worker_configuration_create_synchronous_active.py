"""worker-configuration-create-synchronous-active."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "worker-configuration-create-synchronous-active"
GROUP = "state"
SERVICES = ["kafkaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unlike connectors/plugins, CreateWorkerConfiguration is synchronous: ACTIVE immediately."""
    kc = ctx.client("kafkaconnect")

    props = base64.b64encode(
        b"key.converter=org.apache.kafka.connect.storage.StringConverter\n"
        b"value.converter=org.apache.kafka.connect.storage.StringConverter\n"
    ).decode()
    name = ctx.unique_name("sim2real-kc-workercfg-")
    created = kc.create_worker_configuration(
        name=name, propertiesFileContent=props, tags={"sim2real": "true"}
    )
    wc_arn = created["workerConfigurationArn"]
    ctx.on_cleanup(lambda: kc.delete_worker_configuration(workerConfigurationArn=wc_arn))

    assert created["workerConfigurationState"] == "ACTIVE", created["workerConfigurationState"]
    assert created["latestRevision"]["revision"] == 1, created["latestRevision"]

    described = kc.describe_worker_configuration(workerConfigurationArn=wc_arn)
    assert described["workerConfigurationState"] == "ACTIVE", described["workerConfigurationState"]
    assert described["name"] == name, described["name"]
    assert described["latestRevision"]["revision"] == 1, described["latestRevision"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
