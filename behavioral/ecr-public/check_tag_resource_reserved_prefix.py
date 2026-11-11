"""tag-resource-reserved-prefix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-prefix"
GROUP = 'overly-permissive'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)

    def _cleanup():
        try:
            ecr.delete_repository(repositoryName=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name, resp


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource with an aws: key prefix is refused InvalidTagParameterException with the exact
    message and applies no tag, while a normal key on the same repository is applied."""
    ecr = ctx.client("ecr-public")
    name, resp = _create_repository(ctx, ecr)
    arn = resp["repository"]["repositoryArn"]

    err = _err(
        lambda: ecr.tag_resource(resourceArn=arn, tags=[{"Key": "aws:reserved", "Value": "x"}])
    )
    expected = ("InvalidTagParameterException", "Caller is an end user and not allowed to mutate system tags")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected}, got {err}"

    listed = ecr.list_tags_for_resource(resourceArn=arn)
    keys = [t["Key"] for t in listed["tags"]]
    assert "aws:reserved" not in keys, keys

    ecr.tag_resource(resourceArn=arn, tags=[{"Key": "sim2real-team", "Value": "gallery"}])
    final = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert final.get("sim2real-team") == "gallery", f"positive control tag did not land: {final!r}"

    ecr.delete_repository(repositoryName=name)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
