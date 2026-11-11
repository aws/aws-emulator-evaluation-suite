"""add-tags-and-list-tags."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "add-tags-and-list-tags"
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
    """AddTags on an experiment ARN is visible via ListTags."""
    sm = ctx.client("sagemaker")
    _name, arn = _create_experiment(ctx)
    key = ctx.unique_name("sim2real-behav-" + "tagkey-")

    sm.add_tags(ResourceArn=arn, Tags=[{"Key": key, "Value": "alpha"}])
    tags = sm.list_tags(ResourceArn=arn)["Tags"]
    matching = [t for t in tags if t["Key"] == key]
    assert matching, f"tag {key} not found in {tags}"
    assert matching[0]["Value"] == "alpha", matching


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
