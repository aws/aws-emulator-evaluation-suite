"""tag-resource-nonexistent-pipeline-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-pipeline-rejected"
GROUP = 'tags'
SERVICES = ['codepipeline']

def _account_id(ctx) -> str:
    """The target's account id, the same source on every target."""
    return ctx.account

def _pipeline_arn(ctx, name: str) -> str:
    return f"arn:aws:codepipeline:{ctx.region}:{_account_id(ctx)}:{name}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource against a well-formed ARN for a pipeline that does not exist
    -> ResourceNotFoundException."""
    ev = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-behav-absent-pipeline-")
    arn = _pipeline_arn(ctx, name)
    try:
        ev.tag_resource(resourceArn=arn, tags=[{'key': 'Env', 'value': 'probe'}])
    except ClientError as exc:
        err = exc.response.get("Error", {})
    else:
        raise AssertionError(f"TagResource on absent pipeline {arn} succeeded; expected ResourceNotFoundException")
    assert err.get("Code") == "ResourceNotFoundException", err
    expected = f"Pipeline with name {name} does not exist in account {_account_id(ctx)}."
    assert err.get("Message") == expected, (err.get("Message"), expected)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
