"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-removes-tag"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named keys, leaving the remaining tags intact."""
    client = ctx.client("bedrock-agent-runtime")
    created = client.create_session(tags={"a": "1", "b": "2"})
    session_id = created["sessionId"]
    session_arn = created["sessionArn"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    before = client.list_tags_for_resource(resourceArn=session_arn)["tags"]
    assert before == {"a": "1", "b": "2"}, f"expected {{'a': '1', 'b': '2'}} right after create, got {before}"

    client.untag_resource(resourceArn=session_arn, tagKeys=["a"])

    after = client.list_tags_for_resource(resourceArn=session_arn)["tags"]
    assert after == {"b": "2"}, f"expected only 'b' to survive UntagResource(['a']), got {after}"


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
