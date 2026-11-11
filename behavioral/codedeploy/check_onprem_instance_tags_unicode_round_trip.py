"""onprem-instance-tags-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "onprem-instance-tags-unicode-round-trip"
GROUP = "representation"
SERVICES = ["codedeploy"]

_UNICODE_KEY = "\u540d\u524d-\u30ad\u30fc"
_UNICODE_VALUE = "\u65e5\u672c\u8a9e\u0645\u0631\u062d\u0628\u0627\u041f\u0440\u0438\u0432\u0435\u0442caf\u00e9"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag keys/values applied via AddTagsToOnPremisesInstances are preserved
    exactly (no mangling, truncation, or normalization) when read back via
    GetOnPremisesInstance."""
    cd = ctx.client("codedeploy")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    instance_name = ctx.unique_name("sim2real-cd-onprem-")
    cd.register_on_premises_instance(
        instanceName=instance_name, iamUserArn=f"arn:aws:iam::{account_id}:user/{instance_name}"
    )
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name))

    cd.add_tags_to_on_premises_instances(
        tags=[{"Key": _UNICODE_KEY, "Value": _UNICODE_VALUE}], instanceNames=[instance_name]
    )

    info = cd.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    tags = {t["Key"]: t["Value"] for t in info["tags"]}
    got = tags.get(_UNICODE_KEY)
    assert got == _UNICODE_VALUE, f"expected tag {_UNICODE_KEY!r}={_UNICODE_VALUE!r}, got {got!r} (all tags: {tags})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
