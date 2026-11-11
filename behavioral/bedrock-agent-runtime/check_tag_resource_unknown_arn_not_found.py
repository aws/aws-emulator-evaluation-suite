"""tag-resource-unknown-arn-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-unknown-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against a syntactically valid session ARN that was never created
    returns ResourceNotFoundException, while tagging a real session succeeds and the
    tag round-trips through ListTagsForResource (positive control in the same file)."""
    client = ctx.client("bedrock-agent-runtime")

    session = client.create_session()
    session_id = session["sessionId"]
    session_arn = session["sessionArn"]
    ctx.on_cleanup(lambda: _end_and_delete(ctx, session_id))

    client.tag_resource(resourceArn=session_arn, tags={"env": "sim2real"})
    tags_after = client.list_tags_for_resource(resourceArn=session_arn)["tags"]
    assert tags_after.get("env") == "sim2real", f"expected tag env=sim2real, got {tags_after!r}"

    # Same account/region, well-formed session ARN, but this UUID was never created.
    bogus_arn = session_arn.rsplit("/", 1)[0] + "/" + str(uuid.uuid4())
    code, message = _error(
        lambda: client.tag_resource(resourceArn=bogus_arn, tags={"env": "sim2real"})
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException tagging unknown session arn, got {code!r}"
    )
    expected_message = "Session resource not found."
    assert message == expected_message, (
        f"expected message {expected_message!r} tagging unknown session arn, got {message!r}"
    )

    # Effect absent: no tag was ever recorded for the non-existent resource.
    code_list, message_list = _error(lambda: client.list_tags_for_resource(resourceArn=bogus_arn))
    assert code_list == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException listing tags for unknown session arn, got {code_list!r}"
    )
    expected_list_message = "Session resource not found."
    assert message_list == expected_list_message, (
        f"expected message {expected_list_message!r} listing tags for unknown session arn, "
        f"got {message_list!r}"
    )


def _end_and_delete(ctx, session_id: str) -> None:
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
