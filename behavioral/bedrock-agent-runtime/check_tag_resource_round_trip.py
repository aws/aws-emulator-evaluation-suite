"""tag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-round-trip"
GROUP = "tagging"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a session ARN is visible via ListTagsForResource and removable via UntagResource."""
    client = ctx.client("bedrock-agent-runtime")
    created = client.create_session()
    session_id = created["sessionId"]
    session_arn = created["sessionArn"]

    def _cleanup():
        try:
            client.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            client.delete_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    client.tag_resource(resourceArn=session_arn, tags={"env": "sim2real-check"})
    tags = client.list_tags_for_resource(resourceArn=session_arn)["tags"]
    assert tags == {"env": "sim2real-check"}, f"expected {{'env': 'sim2real-check'}}, got {tags}"

    client.untag_resource(resourceArn=session_arn, tagKeys=["env"])
    tags_after = client.list_tags_for_resource(resourceArn=session_arn).get("tags", {})
    assert "env" not in tags_after, f"expected 'env' removed, still present in {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
