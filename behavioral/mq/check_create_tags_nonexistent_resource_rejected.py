"""create-tags-nonexistent-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tags-nonexistent-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["mq"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags against a syntactically valid but nonexistent configuration ARN is rejected with NotFoundException."""
    mq = ctx.client("mq")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:mq:{ctx.region}:{account_id}:configuration:{ctx.unique_name('c-nonexistent-')}"

    code, message = _error(lambda: mq.create_tags(ResourceArn=bogus_arn, Tags={"k": "v"}))
    assert code == "NotFoundException", code
    assert message == "Resource was not found", message

    # positive control: tagging a real, existing configuration succeeds.
    name = ctx.unique_name("sim2real-mqcfg-")
    created = mq.create_configuration(EngineType="ACTIVEMQ", Name=name)
    config_id = created["Id"]
    ctx.on_cleanup(lambda: mq.delete_configuration(ConfigurationId=config_id))

    mq.create_tags(ResourceArn=created["Arn"], Tags={"k": "v"})
    got = mq.list_tags(ResourceArn=created["Arn"])["Tags"]
    assert got == {"k": "v"}, got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
