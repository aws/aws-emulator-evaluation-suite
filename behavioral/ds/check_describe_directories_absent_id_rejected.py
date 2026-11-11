"""describe-directories-absent-id-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-directories-absent-id-rejected"
GROUP = 'error-semantics'
SERVICES = ['ds']


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message, RequestId) of the ClientError it
    raises. A success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = exc.response.get("ResponseMetadata", {}).get("RequestId")
        return err.get("Code"), err.get("Message"), request_id
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _absent_directory_id() -> str:
    """A DirectoryId that satisfies the model pattern ^d-[0-9a-f]{10}$ but names nothing."""
    return "d-" + uuid.uuid4().hex[:10]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDirectories filtered to one or two absent ids fails with EntityDoesNotExistException and
    "Invalid directory ID(s): ..." rather than returning an empty list, registers neither id, and an
    unminted NextToken fails with a different code, InvalidNextTokenException."""
    ds = ctx.client("ds")

    # Control: the unfiltered inventory read is a legitimate success and must stay one.
    inventory = ds.describe_directories()
    assert isinstance(inventory.get("DirectoryDescriptions"), list), (
        f"unfiltered DescribeDirectories must return a DirectoryDescriptions list: {inventory}"
    )
    known_ids = {d.get("DirectoryId") for d in inventory["DirectoryDescriptions"]}

    absent_one = _absent_directory_id()
    absent_two = _absent_directory_id()
    assert absent_one not in known_ids and absent_two not in known_ids, (
        f"generated ids collided with real directories: {absent_one} {absent_two} vs {known_ids}"
    )

    # Break exactly one thing: filter on an id that does not exist.
    single, single_message, single_rid = _error(lambda: ds.describe_directories(DirectoryIds=[absent_one]))
    assert single == "EntityDoesNotExistException", (
        f"DescribeDirectories(DirectoryIds=[{absent_one}]) must raise "
        f"EntityDoesNotExistException, got {single} — an empty list here means an emulator "
        f"that stores nothing scores a pass"
    )
    expected_single = f"Invalid directory ID(s): {absent_one}. : RequestId: {single_rid}"
    assert single_message == expected_single, (
        f"expected message {expected_single!r}, got {single_message!r}"
    )

    # Two absent ids: still a hard failure, not an empty page.
    both, both_message, both_rid = _error(
        lambda: ds.describe_directories(DirectoryIds=[absent_one, absent_two])
    )
    assert both == "EntityDoesNotExistException", (
        f"DescribeDirectories over two absent ids must raise EntityDoesNotExistException, "
        f"got {both}"
    )
    expected_both = f"Invalid directory ID(s): {absent_one},{absent_two}. : RequestId: {both_rid}"
    assert both_message == expected_both, (
        f"expected message {expected_both!r}, got {both_message!r}"
    )

    # Effect absent: the failed lookups must not have created/registered anything.
    after_ids = {d.get("DirectoryId") for d in ds.describe_directories()["DirectoryDescriptions"]}
    assert absent_one not in after_ids and absent_two not in after_ids, (
        f"failed DescribeDirectories lookups registered {absent_one} or {absent_two}: {after_ids}"
    )

    # Control still validates: a NextToken that ds never minted is a DIFFERENT, specific
    # error, so the service is not funnelling every bad input into one code.
    token, token_message, token_rid = _error(
        lambda: ds.describe_directories(NextToken="sim2real-behav-not-a-real-token")
    )
    assert token == "InvalidNextTokenException", (
        f"an unminted NextToken must raise InvalidNextTokenException (distinct from the "
        f"absent-entity code), got {token}"
    )
    expected_token = f"Invalid value passed for the NextToken parameter. : RequestId: {token_rid}"
    assert token_message == expected_token, (
        f"expected message {expected_token!r}, got {token_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
