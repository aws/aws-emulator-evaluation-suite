"""tag-resource-key-overwrite-on-reapply."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "tag-resource-key-overwrite-on-reapply"
GROUP = "tagging"
SERVICES = ["kafkaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-applying TagResource with an existing key overwrites its value in place (no duplicate entry)."""
    kc = ctx.client("kafkaconnect")

    props = base64.b64encode(
        b"key.converter=org.apache.kafka.connect.storage.StringConverter\n"
        b"value.converter=org.apache.kafka.connect.storage.StringConverter\n"
    ).decode()
    wc_arn = kc.create_worker_configuration(
        name=ctx.unique_name("sim2real-kc-tagover-"), propertiesFileContent=props
    )["workerConfigurationArn"]
    ctx.on_cleanup(lambda: kc.delete_worker_configuration(workerConfigurationArn=wc_arn))

    kc.tag_resource(resourceArn=wc_arn, tags={"Env": "dev"})
    initial = kc.list_tags_for_resource(resourceArn=wc_arn)["tags"]
    assert initial == {"Env": "dev"}, initial

    kc.tag_resource(resourceArn=wc_arn, tags={"Env": "prod"})
    tags = kc.list_tags_for_resource(resourceArn=wc_arn)["tags"]
    assert tags == {"Env": "prod"}, tags
    assert len(tags) == 1, tags


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
