"""get-snapshot-limits-nonexistent-directory."""

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


CHECK = "get-snapshot-limits-nonexistent-directory"
GROUP = 'error-semantics'
SERVICES = ['ds']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSnapshotLimits for a directory that does not exist yields
    EntityDoesNotExistException — and the control plane is otherwise healthy, so the
    rejection is about the absent directory and not a broken client/region/credential."""
    ds = ctx.client("ds")

    # Positive control: an unfiltered inventory read is a legitimate success. Without
    # this, a target that rejects every GetSnapshotLimits call (broken creds, wrong
    # region, no permissions at all) would score identically to one that correctly
    # distinguishes "absent directory" from everything else.
    inventory = ds.describe_directories()
    assert isinstance(inventory.get("DirectoryDescriptions"), list), (
        f"DescribeDirectories must return a DirectoryDescriptions list when the control "
        f"plane is healthy: {inventory}"
    )
    known_ids = {d.get("DirectoryId") for d in inventory["DirectoryDescriptions"]}

    absent_directory_id = "d-" + uuid.uuid4().hex[:10]
    assert absent_directory_id not in known_ids, (
        f"generated id collided with a real directory: {absent_directory_id}"
    )

    code, message, request_id = _client_error(
        lambda: ds.get_snapshot_limits(DirectoryId=absent_directory_id)
    )
    assert code == "EntityDoesNotExistException", (
        f"GetSnapshotLimits(DirectoryId={absent_directory_id!r}) must raise "
        f"EntityDoesNotExistException, got {code!r}"
    )
    expected = f"Directory: '{absent_directory_id}' does not exist. : RequestId: {request_id}"
    assert message == expected, (
        f"GetSnapshotLimits(DirectoryId={absent_directory_id!r}) must refuse with {expected!r}, "
        f"got {message!r}"
    )

    # Effect absent: the failed lookup must not have registered anything.
    after = ds.describe_directories()["DirectoryDescriptions"]
    assert absent_directory_id not in {d.get("DirectoryId") for d in after}, (
        f"a failed GetSnapshotLimits lookup registered {absent_directory_id}: "
        f"{[d.get('DirectoryId') for d in after]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
