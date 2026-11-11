"""tags-create-list-delete-roundtrip-on-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tags-create-list-delete-roundtrip-on-configuration"
GROUP = "state"
SERVICES = ["mq"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags/ListTags/DeleteTags round-trip on a configuration resource; partial delete keeps the rest."""
    mq = ctx.client("mq")
    name = ctx.unique_name("sim2real-mqcfg-")
    created = mq.create_configuration(EngineType="ACTIVEMQ", Name=name)
    config_id = created["Id"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))

    mq.create_tags(ResourceArn=arn, Tags={"team": "sim2real", "stage": "test"})
    tags = mq.list_tags(ResourceArn=arn)["Tags"]
    assert tags == {"team": "sim2real", "stage": "test"}, tags

    mq.delete_tags(ResourceArn=arn, TagKeys=["team"])
    tags_after = mq.list_tags(ResourceArn=arn)["Tags"]
    assert tags_after == {"stage": "test"}, tags_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
