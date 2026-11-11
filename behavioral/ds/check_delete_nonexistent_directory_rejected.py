"""delete-nonexistent-directory-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-directory-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDirectory on an unknown DirectoryId returns EntityDoesNotExistException,
    not a silent success, and leaves no directory under that id in the listing."""
    ds = ctx.client("ds")
    # Well-formed (matches ^d-[0-9a-f]{10}$) but not a real, ever-issued directory id.
    fake_directory_id = "d-" + "0123456789ab"[:10]

    # Positive control: the account's own inventory is readable, and the fake id does not
    # collide with a real directory, before we touch anything.
    known_ids = {d.get("DirectoryId") for d in ds.describe_directories()["DirectoryDescriptions"]}
    assert fake_directory_id not in known_ids, (
        f"generated id {fake_directory_id} collided with a real directory: {known_ids}"
    )

    code, message, request_id = _error(lambda: ds.delete_directory(DirectoryId=fake_directory_id))
    assert code == "EntityDoesNotExistException", f"expected EntityDoesNotExistException, got {code}"
    expected_message = f"Directory: '{fake_directory_id}' does not exist. : RequestId: {request_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Calling it again is still rejected the same way (no partial/latched state was created).
    code_again, message_again, request_id_again = _error(
        lambda: ds.delete_directory(DirectoryId=fake_directory_id)
    )
    assert code_again == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException, got {code_again}"
    )
    expected_message = f"Directory: '{fake_directory_id}' does not exist. : RequestId: {request_id_again}"
    assert message_again == expected_message, (
        f"expected message {expected_message!r}, got {message_again!r}"
    )

    # Terminal read, independent of the mutating calls: the rejected deletes registered no
    # directory under the id.
    after_ids = {d.get("DirectoryId") for d in ds.describe_directories()["DirectoryDescriptions"]}
    assert fake_directory_id not in after_ids, (
        f"rejected deletes left {fake_directory_id} in the directory listing: {after_ids}"
    )


def _error(fn):
    """Call fn(); return the (Code, Message, RequestId) of the ClientError it raises. ds
    embeds the response's own RequestId in the message. A success raises."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
