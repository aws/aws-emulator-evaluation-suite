"""tag-untag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-untag-resource-round-trip"
GROUP = "tagging"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags added to a session via TagResource show up verbatim in ListTagsForResource,
    and UntagResource removes exactly the requested keys, leaving the rest intact."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    session_arn = created["sessionArn"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    client.tag_resource(resourceArn=session_arn, tags={"env": "test", "owner": "sim2real"})
    tags_after_add = client.list_tags_for_resource(resourceArn=session_arn)["tags"]
    assert tags_after_add == {"env": "test", "owner": "sim2real"}, (
        f"expected both tags after TagResource, got {tags_after_add!r}"
    )

    client.untag_resource(resourceArn=session_arn, tagKeys=["owner"])
    tags_after_remove = client.list_tags_for_resource(resourceArn=session_arn)["tags"]
    assert tags_after_remove == {"env": "test"}, (
        f"expected only 'env' to remain after UntagResource(['owner']), got {tags_after_remove!r}"
    )


def _safe_delete_session(client, session_id: str) -> None:
    try:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
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
