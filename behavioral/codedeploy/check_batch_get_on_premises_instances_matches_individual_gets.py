"""batch-get-on-premises-instances-matches-individual-gets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-on-premises-instances-matches-individual-gets"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetOnPremisesInstances returns the same instance info set as individually
    calling GetOnPremisesInstance for each name."""
    cd = ctx.client("codedeploy")

    names = [_register_onprem_instance(ctx, suffix=str(i)) for i in range(2)]

    batch = cd.batch_get_on_premises_instances(instanceNames=names)
    batch_by_name = {info["instanceName"]: info for info in batch["instanceInfos"]}
    assert set(batch_by_name.keys()) == set(names), (
        f"expected batch to cover {set(names)}, got {set(batch_by_name.keys())}"
    )

    for name in names:
        individual = cd.get_on_premises_instance(instanceName=name)["instanceInfo"]
        batch_entry = batch_by_name[name]
        assert batch_entry["iamUserArn"] == individual["iamUserArn"], (
            f"{name}: batch iamUserArn {batch_entry['iamUserArn']!r} != "
            f"individual {individual['iamUserArn']!r}"
        )
        assert batch_entry["instanceArn"] == individual["instanceArn"], (
            f"{name}: batch instanceArn {batch_entry['instanceArn']!r} != "
            f"individual {individual['instanceArn']!r}"
        )
        assert batch_entry["registerTime"] == individual["registerTime"], (
            f"{name}: batch registerTime {batch_entry['registerTime']!r} != "
            f"individual {individual['registerTime']!r}"
        )


def _register_onprem_instance(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    cd = ctx.client("codedeploy")
    user_name = ctx.unique_name(f"sim2real-cdonprem-user-{suffix}-")
    user_arn = iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    instance_name = ctx.unique_name(f"sim2real-onprem-{suffix}-")
    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name))
    cd.add_tags_to_on_premises_instances(
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
        instanceNames=[instance_name],
    )
    return instance_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
