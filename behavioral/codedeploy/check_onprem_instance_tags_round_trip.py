"""onprem-instance-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "onprem-instance-tags-round-trip"
GROUP = "representation"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag keys/values added via AddTagsToOnPremisesInstances survive
    unchanged on GetOnPremisesInstance, and RemoveTagsFromOnPremisesInstances removes
    exactly those tags (no more, no less)."""
    codedeploy = ctx.client("codedeploy")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    instance_name = ctx.unique_name("sim2real-onprem-")
    iam_user_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-user-')}"
    codedeploy.register_on_premises_instance(instanceName=instance_name, iamUserArn=iam_user_arn)
    ctx.on_cleanup(lambda: codedeploy.deregister_on_premises_instance(instanceName=instance_name))

    # Emoji/symbol codepoints trip CodeDeploy's InvalidTagException, so this exercises
    # unicode *letters* across scripts (CJK, Latin-with-diacritics, Katakana) which are
    # accepted, while still being a meaningful non-ASCII round-trip check.
    tags = [
        {"Key": "\u94a5unicode-key", "Value": "\u503cvalue-value"},
        {"Key": "caf\u00e9-key", "Value": "na\u00efve-\u30c6\u30b9\u30c8"},
    ]

    codedeploy.add_tags_to_on_premises_instances(tags=tags, instanceNames=[instance_name])

    info = codedeploy.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    got_tags = {(t["Key"], t["Value"]) for t in info.get("tags", [])}
    want_tags = {(t["Key"], t["Value"]) for t in tags}
    assert got_tags == want_tags, f"tags did not round-trip: got={got_tags} want={want_tags}"

    codedeploy.remove_tags_from_on_premises_instances(tags=tags, instanceNames=[instance_name])

    info_after = codedeploy.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    remaining = {(t["Key"], t["Value"]) for t in info_after.get("tags", [])}
    assert remaining == set(), f"tags were not fully removed: remaining={remaining}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
