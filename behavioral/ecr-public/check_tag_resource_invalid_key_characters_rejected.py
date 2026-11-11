"""tag-resource-invalid-key-characters-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-characters-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so pin that region on the
    target ctx names."""
    from botocore.config import Config

    return ctx.client("ecr-public", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"}))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a tag key that uses the reserved 'aws:' prefix is rejected with
    InvalidTagParameterException -- not silently sanitized and stored under a mangled
    key -- and a normal tag key in the same file still gets applied (positive control)."""
    ecrp = _ecrpub_client(ctx)


    repo_name = ctx.unique_name("sim2real-tagchars-")
    created = ecrp.create_repository(repositoryName=repo_name)
    repo_arn = created["repository"]["repositoryArn"]
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))

    baseline_tags = [{"Key": "sim2real-baseline", "Value": "present"}]
    ecrp.tag_resource(resourceArn=repo_arn, tags=baseline_tags)

    # Break: a tag key using the reserved "aws:" prefix.
    bad_tags = [{"Key": "aws:reserved-key", "Value": "should-not-land"}]
    err = _error(lambda: ecrp.tag_resource(resourceArn=repo_arn, tags=bad_tags))
    expected = ("InvalidTagParameterException", "Caller is an end user and not allowed to mutate system tags")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected}, got {err}"

    # Effect absent: only the baseline tag exists; the reserved-prefix key was not stored
    # under any spelling (raw or sanitized).
    current_tags = {t["Key"]: t["Value"] for t in ecrp.list_tags_for_resource(resourceArn=repo_arn)["tags"]}
    assert current_tags == {"sim2real-baseline": "present"}, (
        f"rejected tag call must not mutate the tag set, got {current_tags!r}"
    )

    # Positive control: a normal, valid tag key is accepted.
    ecrp.tag_resource(resourceArn=repo_arn, tags=[{"Key": "sim2real-team", "Value": "gallery"}])
    final_tags = {t["Key"]: t["Value"] for t in ecrp.list_tags_for_resource(resourceArn=repo_arn)["tags"]}
    assert final_tags.get("sim2real-team") == "gallery", (
        f"expected a valid tag key to be applied after the rejection, got {final_tags!r}"
    )


def _error(fn) -> Any:
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
