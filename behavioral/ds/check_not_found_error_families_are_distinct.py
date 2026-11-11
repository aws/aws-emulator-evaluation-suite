"""not-found-error-families-are-distinct."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "not-found-error-families-are-distinct"
GROUP = 'error-semantics'
SERVICES = ['ds']

# Derived from the Smithy model (directory-service-2015-04-16.json): 53 operations declare
# EntityDoesNotExistException, 27 declare DirectoryDoesNotExistException, and only 3
# (AddRegion, Enable/DisableCAEnrollmentPolicy) declare both. Which family an operation
# belongs to is a hard contract fact, not a message detail — so the SAME absent DirectoryId
# must produce DIFFERENT codes depending on which operation you call.
# Every call below is an explicit `ds.<op>(...)` attribute call, not a getattr() loop, so the
# operations exercised are statically visible.


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise.
    An unexpected SUCCESS raises, so it never reads as a code mismatch. ds echoes the
    refused call's RequestId in its message, so the caller needs it to build the exact text."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _absent_directory_id() -> str:
    """A DirectoryId that satisfies the model pattern ^d-[0-9a-f]{10}$ but names nothing."""
    return "d-" + uuid.uuid4().hex[:10]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One absent DirectoryId sent to six operations yields two distinct not-found codes: each
    operation returns exactly the family its Smithy shape declares (EntityDoesNotExistException or
    DirectoryDoesNotExistException), never one shared "not found"."""
    ds = ctx.client("ds")
    absent = _absent_directory_id()

    # Control: the same operations succeed at account scope, so the client, region and
    # credentials are good and only the DirectoryId is broken.
    assert isinstance(ds.describe_snapshots().get("Snapshots"), list), (
        "account-scoped DescribeSnapshots must succeed before we test the absent-id path"
    )
    assert isinstance(ds.list_log_subscriptions().get("LogSubscriptions"), list), (
        "account-scoped ListLogSubscriptions must succeed before we test the absent-id path"
    )

    not_found = f"Directory: '{absent}' does not exist."
    entity_errors = {
        "GetSnapshotLimits": _client_error(
            lambda: ds.get_snapshot_limits(DirectoryId=absent)
        ),
        "DescribeSnapshots": _client_error(
            lambda: ds.describe_snapshots(DirectoryId=absent)
        ),
        "ListLogSubscriptions": _client_error(
            lambda: ds.list_log_subscriptions(DirectoryId=absent)
        ),
    }
    directory_errors = {
        "DescribeSettings": _client_error(lambda: ds.describe_settings(DirectoryId=absent)),
        "DescribeDirectoryDataAccess": _client_error(
            lambda: ds.describe_directory_data_access(DirectoryId=absent)
        ),
        "ListCertificates": _client_error(lambda: ds.list_certificates(DirectoryId=absent)),
    }
    # The exact refusal text per operation; DescribeSnapshots words it differently.
    expected_text = {
        "GetSnapshotLimits": not_found,
        "DescribeSnapshots": f"Invalid directory ID: {absent}.",
        "ListLogSubscriptions": not_found,
        "DescribeSettings": not_found,
        "DescribeDirectoryDataAccess": not_found,
        "ListCertificates": not_found,
    }
    entity_codes = {op: err[0] for op, err in entity_errors.items()}
    directory_codes = {op: err[0] for op, err in directory_errors.items()}

    for op, code in entity_codes.items():
        assert code == "EntityDoesNotExistException", (
            f"ds.{op}(DirectoryId={absent}) must raise EntityDoesNotExistException "
            f"(the error its Smithy shape declares), got {code}"
        )
    for op, code in directory_codes.items():
        assert code == "DirectoryDoesNotExistException", (
            f"ds.{op}(DirectoryId={absent}) must raise DirectoryDoesNotExistException "
            f"(the error its Smithy shape declares), got {code}"
        )
    for op, (_code, message, request_id) in {**entity_errors, **directory_errors}.items():
        expected = f"{expected_text[op]} : RequestId: {request_id}"
        assert message == expected, (
            f"ds.{op}(DirectoryId={absent}) must refuse with {expected!r}, got {message!r}"
        )

    # The two families must genuinely be two, not one code answering everything.
    assert set(entity_codes.values()).isdisjoint(set(directory_codes.values())), (
        f"the two not-found families collapsed into one code: entity={entity_codes} "
        f"directory={directory_codes}"
    )

    # Effect absent: none of the six failed calls conjured the directory into existence.
    after, after_message, after_request = _client_error(
        lambda: ds.describe_directories(DirectoryIds=[absent])
    )
    assert after == "EntityDoesNotExistException", (
        f"after six failed operations, {absent} must still be absent "
        f"(DescribeDirectories should raise EntityDoesNotExistException), got {after}"
    )
    expected = f"Invalid directory ID(s): {absent}. : RequestId: {after_request}"
    assert after_message == expected, (
        f"DescribeDirectories(DirectoryIds=[{absent}]) must refuse with {expected!r}, "
        f"got {after_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
