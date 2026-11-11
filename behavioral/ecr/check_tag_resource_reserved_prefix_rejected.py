"""tag-resource-reserved-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

CHECK = "tag-resource-reserved-prefix-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource with a reserved 'aws:' key prefix is rejected, while an ordinary tag succeeds;
    ListTagsForResource then shows the reserved tag was never stored and the ordinary one remains."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    repo = _create_repo(ecr, ctx, name)
    arn = repo["repositoryArn"]

    ecr.tag_resource(resourceArn=arn, tags=[{"Key": "team", "Value": "platform"}])
    after_control = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert after_control == {"team": "platform"}, after_control

    error = _client_error(
        lambda: ecr.tag_resource(resourceArn=arn, tags=[{"Key": "aws:reserved", "Value": "x"}])
    )
    code = error.get("Code")
    assert code == "InvalidTagParameterException", f"expected InvalidTagParameterException, got {code}"
    assert error.get("Message") == (
        "Caller is an end user and not allowed to mutate system tags"
    ), error.get("Message")

    after_rejected = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert "aws:reserved" not in after_rejected, "reserved-prefixed tag must never be stored"
    assert after_rejected == {"team": "platform"}, "rejected call must not disturb existing tags"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
