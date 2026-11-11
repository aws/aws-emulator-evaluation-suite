"""add-tags-overwrites-existing-key."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "add-tags-overwrites-existing-key"
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
    """Re-adding an existing key replaces its value (last-writer-wins).

    AddTags with the same key and a new value updates the value rather than duplicating the key.
    """
    sm = ctx.client("sagemaker")
    _name, arn = _create_experiment(ctx)
    key = ctx.unique_name("sim2real-behav-" + "tagkey-")

    sm.add_tags(ResourceArn=arn, Tags=[{"Key": key, "Value": "alpha"}])
    sm.add_tags(ResourceArn=arn, Tags=[{"Key": key, "Value": "beta"}])

    tags = sm.list_tags(ResourceArn=arn)["Tags"]
    matching = [t for t in tags if t["Key"] == key]
    assert len(matching) == 1, f"key {key} duplicated: {matching}"
    assert matching[0]["Value"] == "beta", matching


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
