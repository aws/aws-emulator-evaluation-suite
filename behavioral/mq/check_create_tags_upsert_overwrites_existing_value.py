"""create-tags-upsert-overwrites-existing-value."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-tags-upsert-overwrites-existing-value"
GROUP = "state"
SERVICES = ["mq"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags with an existing tag key overwrites its value instead of erroring or duplicating."""
    mq = ctx.client("mq")
    name = ctx.unique_name("sim2real-mqcfg-")
    created = mq.create_configuration(EngineType="ACTIVEMQ", Name=name)
    config_id = created["Id"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))

    mq.create_tags(ResourceArn=arn, Tags={"env": "first-value"})
    first_tags = mq.list_tags(ResourceArn=arn)["Tags"]
    assert first_tags == {"env": "first-value"}, first_tags

    mq.create_tags(ResourceArn=arn, Tags={"env": "second-value"})
    tags = mq.list_tags(ResourceArn=arn)["Tags"]
    assert tags == {"env": "second-value"}, tags


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
