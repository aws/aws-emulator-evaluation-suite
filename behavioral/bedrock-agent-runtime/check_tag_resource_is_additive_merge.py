"""tag-resource-is-additive-merge."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-is-additive-merge"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges new tags with existing ones rather than replacing the whole tag set."""
    client = ctx.client("bedrock-agent-runtime")
    created = client.create_session(tags={"a": "1"})
    session_id = created["sessionId"]
    session_arn = created["sessionArn"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    client.tag_resource(resourceArn=session_arn, tags={"b": "2"})

    tags = client.list_tags_for_resource(resourceArn=session_arn)["tags"]
    assert tags == {"a": "1", "b": "2"}, (
        f"expected TagResource to merge with the existing tag set, got {tags}"
    )


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
