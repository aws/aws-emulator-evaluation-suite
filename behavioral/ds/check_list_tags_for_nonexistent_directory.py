"""list-tags-for-nonexistent-directory."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


CHECK = "list-tags-for-nonexistent-directory"
GROUP = 'tags'
SERVICES = ['ds']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource against a directory id that does not exist is rejected
    (does not fabricate an empty tag set for a phantom resource)."""
    ds = ctx.client("ds")
    absent = "d-" + uuid.uuid4().hex[:10]
    code, message, request_id = _client_error(
        lambda: ds.list_tags_for_resource(ResourceId=absent)
    )
    assert code == "EntityDoesNotExistException", (
        f"ListTagsForResource(ResourceId={absent!r}) on a directory id that does not exist "
        f"must raise EntityDoesNotExistException (the only not-found error the shape "
        f"declares), got {code!r}"
    )
    # ds appends the RequestId twice to this message.
    expected = f"Invalid resource ID. : RequestId: {request_id} : RequestId: {request_id}"
    assert message == expected, (
        f"ListTagsForResource(ResourceId={absent!r}) must refuse with {expected!r}, got {message!r}"
    )

    # Control: the account-scoped read path is healthy, so the refusal above is about the
    # absent resource id and not a broken client, region or credential.
    assert isinstance(
        ds.describe_directories().get("DirectoryDescriptions"), list
    ), "DescribeDirectories must still succeed after the refused ListTagsForResource call"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
