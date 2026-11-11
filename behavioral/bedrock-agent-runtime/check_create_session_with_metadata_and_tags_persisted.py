"""create-session-with-metadata-and-tags-persisted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-session-with-metadata-and-tags-persisted"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession accepts sessionMetadata and tags at creation time, and both are readable
    back immediately (sessionMetadata via GetSession, tags via ListTagsForResource) without a
    separate Update/Tag call."""
    client = ctx.client("bedrock-agent-runtime")

    metadata = {"userId": "sim2real-user-1", "locale": "en-US"}
    tags = {"env": "test"}
    created = client.create_session(sessionMetadata=metadata, tags=tags)
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

    got = client.get_session(sessionIdentifier=session_id)
    assert got["sessionMetadata"] == metadata, (
        f"expected sessionMetadata {metadata!r} from GetSession, "
        f"got {got['sessionMetadata']!r}"
    )

    listed_tags = client.list_tags_for_resource(resourceArn=session_arn)
    assert listed_tags["tags"] == tags, (
        f"expected tags {tags!r} from ListTagsForResource, got {listed_tags['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
