"""ds-data-is-a-distinct-validated-surface."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError, UnknownServiceError

from behavioral_harness import tags

CHECK = "ds-data-is-a-distinct-validated-surface"
GROUP = 'directory-data'
SERVICES = ['ds']
# ds-data is a separate Smithy model, protocol and endpoint from ds: restJson1 rather than
# awsJson1.1, signing name "ds-data", and REST paths such as POST /Users/DescribeUser.

_ABSENT_DIRECTORY_LEGAL_USER = "sim2real-behav"
_ILLEGAL_USER = "sim2real:behav"       # ':' is outside UserName's ^[\w\-.]+$
_OVERLONG_USER = "s" * 21              # UserName length max is 20 (max is NOT client-validated)


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _request_id_error(fn):
    """Like _error, plus the RequestId of the refused call, which ds echoes in its message."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _absent_directory_id() -> str:
    """A DirectoryId that satisfies the modeled pattern ^d-[0-9a-f]{10}$ but names nothing."""
    return "d-" + uuid.uuid4().hex[:10]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For one absent DirectoryId, ds-data answers AccessDeniedException without disclosing absence,
    while ds answers EntityDoesNotExist/DirectoryDoesNotExist naming it; ds-data validates member
    constraints (exact messages) before authorization.

    Reference: https://docs.aws.amazon.com/directoryservicedata/latest/DirectoryServiceDataAPIReference/API_DescribeUser.html
    """
    ds = ctx.client("ds")
    try:
        dsd = ctx.client("ds-data")
    except UnknownServiceError as exc:
        raise AssertionError(
            f"botocore in this environment has no ds-data service model: {exc}"
        ) from exc

    absent = _absent_directory_id()
    # The authorization refusal names the calling principal, so it is built from the caller's own
    # identity as the target reports it.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    denied_message = f"User: {caller_arn} is not authorized to access this resource"

    # A well-formed request whose only fault is that the directory does not exist.
    not_found, not_found_message = _error(
        lambda: dsd.describe_user(
            DirectoryId=absent, SAMAccountName=_ABSENT_DIRECTORY_LEGAL_USER
        )
    )
    assert not_found == "AccessDeniedException", (
        f"ds-data DescribeUser(DirectoryId={absent}) must raise AccessDeniedException — ds-data "
        f"declines to confirm or deny that a directory exists, so it never surfaces the "
        f"ResourceNotFoundException its own shape declares for an absent DirectoryId — got "
        f"{not_found} (None means it fabricated a user for a directory that does not exist)"
    )
    assert not_found_message == denied_message, (
        f"the refusal must be ds-data's resource-authorization refusal, got {not_found_message!r}"
    )
    # Not a leak: the refusal must not disclose whether the directory exists.
    assert "does not exist" not in not_found_message and absent not in not_found_message, (
        f"an authorization refusal that names the directory or its absence defeats the point of "
        f"answering AccessDenied instead of NotFound, got {not_found_message!r}"
    )
    # And not an IAM policy denial either, which has a different, action-naming form. This is
    # what makes AccessDeniedException here a SERVICE behaviour worth emulating rather than an
    # artefact of the caller's permissions.
    assert "no identity-based policy allows" not in not_found_message, (
        f"this must be ds-data's own resource authorization, not an IAM implicit deny, got "
        f"{not_found_message!r}"
    )
    # The same code from a DIFFERENT ds-data operation on the same absent directory, so it is a
    # property of the surface rather than a DescribeUser quirk.
    other_op, other_message = _error(lambda: dsd.list_groups(DirectoryId=absent))
    assert other_op == "AccessDeniedException", (
        f"ds-data ListGroups(DirectoryId={absent}) must be refused the same way as DescribeUser, "
        f"got {other_op}"
    )
    assert other_message == not_found_message, (
        f"the whole ds-data surface must answer an unreachable directory with one refusal, got "
        f"{other_message!r} vs {not_found_message!r}"
    )

    # The three not-found families must be three. ds and ds-data share the DirectoryId namespace
    # but not their error vocabularies, so an emulator backing both with one store fails here.
    ds_entity, entity_message, entity_request = _request_id_error(
        lambda: ds.get_snapshot_limits(DirectoryId=absent)
    )
    ds_directory, directory_message, directory_request = _request_id_error(
        lambda: ds.describe_settings(DirectoryId=absent)
    )
    assert ds_entity == "EntityDoesNotExistException", (
        f"ds GetSnapshotLimits(DirectoryId={absent}) must raise EntityDoesNotExistException, got "
        f"{ds_entity}"
    )
    assert ds_directory == "DirectoryDoesNotExistException", (
        f"ds DescribeSettings(DirectoryId={absent}) must raise DirectoryDoesNotExistException, "
        f"got {ds_directory}"
    )
    # ds itself DOES disclose non-existence, and names the directory: the exact opposite of
    # ds-data's refusal above. That contrast is the check's whole point, so assert both halves.
    for label, message, request_id in (
        ("GetSnapshotLimits", entity_message, entity_request),
        ("DescribeSettings", directory_message, directory_request),
    ):
        assert message == f"Directory: '{absent}' does not exist. : RequestId: {request_id}", (
            f"ds {label} must state plainly that the directory does not exist and name it — "
            f"unlike ds-data, which refuses to disclose that — got {message!r}"
        )
    assert len({not_found, ds_entity, ds_directory}) == 3, (
        f"the same absent DirectoryId must produce three distinct not-found codes across the two "
        f"APIs: ds-data={not_found}, ds/entity={ds_entity}, ds/directory={ds_directory}"
    )

    # Validation precedes AUTHORIZATION, member by member. Each message names the offending
    # member and the constraint it violated, so no two legs can be satisfied by one string.
    illegal, illegal_message = _error(
        lambda: dsd.describe_user(DirectoryId=absent, SAMAccountName=_ILLEGAL_USER)
    )
    assert illegal == "ValidationException", (
        f"ds-data DescribeUser(SAMAccountName={_ILLEGAL_USER!r}) must be refused with "
        f"ValidationException — ':' is outside UserName's ^[\\w\\-.]+$ — got {illegal}"
    )
    # An ordinary (non-@sensitive) member has its VALUE echoed back, unlike ds's Password, and
    # the refusal quotes the pattern the value failed.
    assert illegal_message == (
        f"1 validation error detected: Value '{_ILLEGAL_USER}' at 'sAMAccountName' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: [\\w\\-.]+"
    ), f"the refusal must echo the value and quote the pattern it failed, got {illegal_message!r}"

    overlong, overlong_message = _error(
        lambda: dsd.describe_user(DirectoryId=absent, SAMAccountName=_OVERLONG_USER)
    )
    assert overlong == "ValidationException", (
        f"ds-data DescribeUser with a 21-character SAMAccountName must be refused with "
        f"ValidationException (UserName length max is 20; botocore validates only `min`, so this "
        f"reaches the service), got {overlong}"
    )
    # A LENGTH violation, distinguished from the pattern violation above: same code, same member,
    # different constraint. _OVERLONG_USER satisfies ^[\w\-.]+$, so only the max can refuse it.
    assert overlong_message == (
        f"1 validation error detected: Value '{_OVERLONG_USER}' at 'sAMAccountName' failed to "
        f"satisfy constraint: Member must have length less than or equal to 20"
    ), f"the refusal must name the length bound, not the pattern, got {overlong_message!r}"

    over_max_results, mr_message = _error(
        lambda: dsd.list_users(DirectoryId=absent, MaxResults=251)
    )
    assert over_max_results == "ValidationException", (
        f"ds-data ListUsers(MaxResults=251) must be refused with ValidationException (MaxResults "
        f"range is 1-250 and botocore does not client-validate the max), got {over_max_results}"
    )
    assert mr_message == (
        "1 validation error detected: Value '251' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 250"
    ), f"the refusal must name the numeric bound it enforced, got {mr_message!r}"

    bad_attribute, attr_message = _error(
        lambda: dsd.search_users(
            DirectoryId=absent,
            SearchString="sim2real",
            SearchAttributes=["1BadAttribute"],
        )
    )
    assert bad_attribute == "ValidationException", (
        f"ds-data SearchUsers(SearchAttributes=['1BadAttribute']) must be refused with "
        f"ValidationException — LdapDisplayName is ^[A-Za-z*][A-Za-z-*]*$, so it cannot start "
        f"with a digit — got {bad_attribute}"
    )
    assert attr_message == (
        "1 validation error detected: Value '[1BadAttribute]' at 'searchAttributes' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must have length less than "
        "or equal to 63, Member must have length greater than or equal to 1, Member must satisfy "
        "regular expression pattern: [A-Za-z*][A-Za-z-*]*]"
    ), f"the refusal must attribute itself to the list member, got {attr_message!r}"

    # THE ORDERING PROOF: a malformed DirectoryId never reaches the authorization layer that
    # refuses a well-formed absent one, so validation strictly precedes authorization.
    malformed_dir, malformed_message = _error(
        lambda: dsd.describe_user(
            DirectoryId="not-a-dir", SAMAccountName=_ABSENT_DIRECTORY_LEGAL_USER
        )
    )
    assert malformed_dir == "ValidationException", (
        f"a DirectoryId that violates ^d-[0-9a-f]{{10}}$ must be refused by validation, not by "
        f"the AccessDeniedException that a well-formed absent id gets, got {malformed_dir}"
    )
    assert malformed_message == (
        "1 validation error detected: Value 'not-a-dir' at 'directoryId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: d-[0-9a-f]{10}"
    ), f"the refusal must quote the DirectoryId pattern, got {malformed_message!r}"
    assert malformed_dir != not_found, (
        "the same member with a malformed value and with a well-formed-but-unreachable value "
        f"must not produce one code ({not_found!r})"
    )

    assert illegal != not_found, (
        f"an invalid member and an absent directory must not share one ds-data code "
        f"({not_found!r})"
    )

    # Control: the ds control plane is still healthy, so the refusals above are about ds-data.
    assert isinstance(
        ds.describe_directories().get("DirectoryDescriptions"), list
    ), "ds DescribeDirectories must still succeed after the ds-data refusals"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
