"""tag-value-empty-string-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-empty-string-preserved"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag with an empty-string Value round-trips through TagResource/DescribeSecret without
    being dropped or coerced."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-tagempty-")

    sm.create_secret(Name=name, SecretString="v")
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    sm.tag_resource(SecretId=name, Tags=[{"Key": "Env", "Value": ""}, {"Key": "Team", "Value": "platform"}])

    desc = sm.describe_secret(SecretId=name)
    tags_by_key = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}

    assert "Env" in tags_by_key, "tag with empty-string Value was dropped entirely"
    assert tags_by_key["Env"] == "", "empty-string tag Value was coerced to something else"
    assert tags_by_key.get("Team") == "platform", "sibling non-empty tag was affected"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
