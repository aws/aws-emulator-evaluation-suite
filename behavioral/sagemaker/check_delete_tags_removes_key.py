"""delete-tags-removes-key."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "delete-tags-removes-key"
GROUP = 'tags'
SERVICES = ['sagemaker']

def _create_experiment(ctx, name=None, display_name="behav-experiment"):
    sm = ctx.client("sagemaker")
    name = name or ctx.unique_name("sim2real-behav-experiment-")
    arn = sm.create_experiment(ExperimentName=name, DisplayName=display_name)["ExperimentArn"]
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=name))
    return name, arn

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTags removes exactly the listed key, leaving other tags intact."""
    sm = ctx.client("sagemaker")
    _name, arn = _create_experiment(ctx)
    keep = ctx.unique_name("sim2real-behav-" + "keep-")
    drop = ctx.unique_name("sim2real-behav-" + "drop-")

    sm.add_tags(
        ResourceArn=arn,
        Tags=[{"Key": keep, "Value": "v"}, {"Key": drop, "Value": "v"}],
    )
    sm.delete_tags(ResourceArn=arn, TagKeys=[drop])

    tags = sm.list_tags(ResourceArn=arn)["Tags"]
    keys = {t["Key"] for t in tags}
    assert drop not in keys, f"{drop} still present: {tags}"
    assert keep in keys, f"{keep} unexpectedly removed: {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
