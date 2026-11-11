"""untag-resource-nonexistent-key-is-noop."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-nonexistent-key-is-noop"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource for a tag key that was never set on the resource is a no-op: it does not
    error, and the existing tags are left completely untouched."""
    client = ctx.client("bedrock-agent-runtime")
    created = client.create_session(tags={"a": "1"})
    session_id = created["sessionId"]
    session_arn = created["sessionArn"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    client.untag_resource(resourceArn=session_arn, tagKeys=["never-set-key"])

    tags = client.list_tags_for_resource(resourceArn=session_arn)["tags"]
    assert tags == {"a": "1"}, f"expected tags unchanged as {{'a': '1'}}, got {tags!r}"


def _safe_end_and_delete(ctx, session_id: str) -> None:
    client = ctx.client("bedrock-agent-runtime")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
