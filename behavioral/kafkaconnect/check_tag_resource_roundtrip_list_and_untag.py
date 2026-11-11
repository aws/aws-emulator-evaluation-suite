"""tag-resource-roundtrip-list-and-untag."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "tag-resource-roundtrip-list-and-untag"
GROUP = "tagging"
SERVICES = ["kafkaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource; UntagResource removes them individually."""
    kc = ctx.client("kafkaconnect")

    props = base64.b64encode(
        b"key.converter=org.apache.kafka.connect.storage.StringConverter\n"
        b"value.converter=org.apache.kafka.connect.storage.StringConverter\n"
    ).decode()
    wc_arn = kc.create_worker_configuration(
        name=ctx.unique_name("sim2real-kc-tagrt-"), propertiesFileContent=props
    )["workerConfigurationArn"]
    ctx.on_cleanup(lambda: kc.delete_worker_configuration(workerConfigurationArn=wc_arn))

    initial_tags = kc.list_tags_for_resource(resourceArn=wc_arn)["tags"]
    assert initial_tags == {}, initial_tags

    kc.tag_resource(resourceArn=wc_arn, tags={"Team": "streaming", "Env": "test"})
    tags = kc.list_tags_for_resource(resourceArn=wc_arn)["tags"]
    assert tags == {"Team": "streaming", "Env": "test"}, tags

    kc.untag_resource(resourceArn=wc_arn, tagKeys=["Env"])
    tags = kc.list_tags_for_resource(resourceArn=wc_arn)["tags"]
    assert tags == {"Team": "streaming"}, tags

    kc.untag_resource(resourceArn=wc_arn, tagKeys=["Team"])
    tags = kc.list_tags_for_resource(resourceArn=wc_arn)["tags"]
    assert tags == {}, tags


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
