"""on-premises-instance-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "on-premises-instance-tags-round-trip"
GROUP = "representation"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags added via AddTagsToOnPremisesInstances are returned unchanged by
    GetOnPremisesInstance, and RemoveTagsFromOnPremisesInstances removes exactly those
    tags, leaving no residue."""
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    instance_name = ctx.unique_name("sim2real-cdonprem-")
    iam_user_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cduser-')}"
    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=iam_user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name))

    tags = [
        {"Key": "sim2real-env", "Value": "staging"},
        {"Key": "sim2real-role", "Value": "worker"},
    ]
    cd.add_tags_to_on_premises_instances(tags=tags, instanceNames=[instance_name])

    resp = cd.get_on_premises_instance(instanceName=instance_name)
    got_tags = sorted(resp["instanceInfo"]["tags"], key=lambda t: t["Key"])
    want_tags = sorted(tags, key=lambda t: t["Key"])
    assert got_tags == want_tags, f"expected {want_tags}, got {got_tags}"

    cd.remove_tags_from_on_premises_instances(tags=tags, instanceNames=[instance_name])
    resp2 = cd.get_on_premises_instance(instanceName=instance_name)
    remaining = resp2["instanceInfo"].get("tags", [])
    assert remaining == [], f"expected no tags after removal, got {remaining}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
