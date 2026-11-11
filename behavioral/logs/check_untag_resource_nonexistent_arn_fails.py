"""untag-resource-nonexistent-arn-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-arn-fails"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource against a log-group ARN that was never created raises
    ResourceNotFoundException instead of silently succeeding; the same call
    against a real, tagged log group actually removes the tag."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_name = ctx.unique_name("sim2real-behav-notexist-")
    bogus_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{bogus_name}"

    code, message = _client_error(
        lambda: logs.untag_resource(resourceArn=bogus_arn, tagKeys=["k"])
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException untagging a non-existent resource, got {code}"
    )
    assert message == "The specified log group does not exist.", (
        f"unexpected message untagging a non-existent resource: {message!r}"
    )

    # Positive control: UntagResource against a real, tagged log group actually
    # removes the tag. Without this, "rejects a non-existent ARN" is
    # indistinguishable from "rejects every UntagResource call".
    log_group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    described = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
    assert len(described) == 1, f"expected exactly one matching log group, got {described!r}"
    arn = described[0]["arn"]
    # describe_log_groups returns the ARN with a trailing ":*" wildcard suffix;
    # the tagging APIs (ListTagsForResource/TagResource/UntagResource) reject
    # that suffix with ValidationException, so it must be stripped before use.
    if arn.endswith(":*"):
        arn = arn[: -len(":*")]

    logs.tag_resource(resourceArn=arn, tags={"sim2real-behav": "probe"})
    before = logs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert before.get("sim2real-behav") == "probe", f"tag was not applied: {before!r}"

    logs.untag_resource(resourceArn=arn, tagKeys=["sim2real-behav"])
    after = logs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-behav" not in after, f"tag was not removed: {after!r}"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
