"""absent-directory-is-denied-rather-than-reported-missing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "absent-directory-is-denied-rather-than-reported-missing"
GROUP = 'directory-data-denied'
SERVICES = ['ds-data']
# Also calls ds (the control plane) for the disclosure contrast and for the positive control.

# Every ds-data operation, as (attribute, kwargs-without-DirectoryId); the claim is about the whole
# surface.
_ALL_OPERATIONS = (
    ("list_users", {}),
    ("describe_user", {"SAMAccountName": "sim2real-behav-u"}),
    ("search_users", {"SearchString": "sim2real", "SearchAttributes": ["SAMAccountName"]}),
    ("create_user", {"SAMAccountName": "sim2real-behav-u"}),
    ("update_user", {"SAMAccountName": "sim2real-behav-u", "GivenName": "Sim"}),
    ("disable_user", {"SAMAccountName": "sim2real-behav-u"}),
    ("delete_user", {"SAMAccountName": "sim2real-behav-u"}),
    ("list_groups", {}),
    ("describe_group", {"SAMAccountName": "sim2real-behav-g"}),
    ("search_groups", {"SearchString": "sim2real", "SearchAttributes": ["SAMAccountName"]}),
    ("create_group", {"SAMAccountName": "sim2real-behav-g"}),
    ("update_group", {"SAMAccountName": "sim2real-behav-g", "GroupScope": "Global"}),
    ("delete_group", {"SAMAccountName": "sim2real-behav-g"}),
    ("list_group_members", {"SAMAccountName": "sim2real-behav-g"}),
    ("list_groups_for_member", {"SAMAccountName": "sim2real-behav-u"}),
    ("add_group_member", {"GroupName": "sim2real-behav-g", "MemberName": "sim2real-behav-u"}),
    ("remove_group_member", {"GroupName": "sim2real-behav-g", "MemberName": "sim2real-behav-u"}),
)

# The operations whose model declares ResourceNotFoundException.
_DECLARE_RESOURCE_NOT_FOUND = frozenset({
    "add_group_member", "delete_group", "delete_user", "describe_group", "describe_user",
    "disable_user", "list_group_members", "list_groups_for_member", "remove_group_member",
    "update_group", "update_user",
})


def _refusal(fn):
    """Call fn(); return (Code, Message, Reason, status, RequestId) of the ClientError it raises.

    An unexpected success raises rather than returning a sentinel.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {}) or {}
        return (
            error.get("Code"),
            error.get("Message") or "",
            exc.response.get("Reason"),
            (exc.response.get("ResponseMetadata") or {}).get("HTTPStatusCode"),
            (exc.response.get("ResponseMetadata") or {}).get("RequestId"),
        )
    raise AssertionError(
        f"the call was expected to be refused but SUCCEEDED with {result!r}"
    )


def _owned_directory_ids(ds) -> set:
    """Every DirectoryId this account holds, paginated so an absent id is provably absent."""
    owned = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = ds.describe_directories(**kwargs)
        for description in page.get("DirectoryDescriptions") or []:
            owned.add(description.get("DirectoryId"))
        token = page.get("NextToken")
        if not token:
            return owned


def _absent_directory_id(ds) -> str:
    """A DirectoryId matching ^d-[0-9a-f]{10}$ that this account demonstrably does not hold."""
    owned = _owned_directory_ids(ds)
    for candidate in (f"d-{n:010x}" for n in range(0x4F8A1C07E2, 0x4F8A1C07E2 + 64)):
        if candidate not in owned:
            return candidate
    raise AssertionError(f"could not find an unissued DirectoryId; owned={sorted(owned)}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every ds-data operation answers an absent DirectoryId with one identical 403
    AccessDeniedException (Reason IAM_AUTH, naming only the caller); ds reports the id as missing.
    """
    ds = ctx.client("ds")
    dsd = ctx.client("ds-data")

    absent = _absent_directory_id(ds)
    # The refusal names the CALLER's principal and nothing else.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected_refusal = f"User: {caller_arn} is not authorized to access this resource"

    envelopes = {}
    for operation, kwargs in _ALL_OPERATIONS:
        call = getattr(dsd, operation)
        # The RequestId differs per call, so the envelope compared across operations omits it.
        envelopes[operation] = _refusal(
            lambda call=call, kwargs=kwargs: call(DirectoryId=absent, **kwargs)
        )[:4]

    assert len(envelopes) == 17, (
        f"ds-data has seventeen operations and every one must be exercised, got "
        f"{sorted(envelopes)}"
    )

    for operation, (code, message, reason, status) in sorted(envelopes.items()):
        assert code == "AccessDeniedException", (
            f"ds-data {operation}(DirectoryId={absent}) must be refused with "
            f"AccessDeniedException -- ds-data never confirms or denies that a directory exists -- "
            f"got {code!r} (a ResourceNotFoundException here is the model-driven answer and the "
            f"exact infidelity this check exists to catch)"
        )
        assert status == 403, (
            f"ds-data {operation} must refuse an unreachable directory with HTTP 403, got {status!r}"
        )
        assert reason == "IAM_AUTH", (
            f"ds-data {operation} must classify the refusal as Reason IAM_AUTH -- not the "
            f"DIRECTORY_AUTH or DATA_DISABLED that AccessDeniedReason also defines -- got "
            f"{reason!r}"
        )
        assert message == expected_refusal, (
            f"ds-data {operation} must refuse by naming the CALLER's own principal ARN and nothing "
            f"else -- {expected_refusal!r} -- got {message!r}"
        )
        # The refusal must not leak what it declined to confirm.
        assert absent not in message and "does not exist" not in message, (
            f"ds-data {operation} answered AccessDenied instead of NotFound and then disclosed "
            f"the directory anyway, which defeats the point: {message!r}"
        )
        # Not an IAM implicit deny: that form names the action and the policy evaluation.
        assert "no identity-based policy allows" not in message and "to perform:" not in message, (
            f"ds-data {operation}'s refusal must be the service's own resource authorization, not "
            f"an IAM implicit deny, got {message!r}"
        )

    # THE UNIFORMITY CLAIM. One answer, byte for byte, across the whole surface.
    distinct = set(envelopes.values())
    assert len(distinct) == 1, (
        f"an unreachable DirectoryId must produce ONE envelope across all seventeen ds-data "
        f"operations; got {len(distinct)} distinct ones: "
        f"{ {op: env for op, env in envelopes.items()} }"
    )

    # Name the operations that declare ResourceNotFoundException in the failure.
    not_found = {
        operation: envelopes[operation][0]
        for operation in _DECLARE_RESOURCE_NOT_FOUND
        if envelopes[operation][0] == "ResourceNotFoundException"
    }
    assert not not_found, (
        f"ResourceNotFoundException is declared by eleven ds-data operations and reachable by none "
        f"of them for an absent directory, but these answered with it: {not_found}"
    )

    # THE CONTRAST. The same account, the same id, one API over: ds says plainly that it does not
    # exist -- and DescribeDirectoryDataAccess is the operation whose entire job is to report
    # whether ds-data can be used, so this is the disclosure ds-data is declining to make.
    ds_code, ds_message, ds_reason, ds_status, ds_request_id = _refusal(
        lambda: ds.describe_directory_data_access(DirectoryId=absent)
    )
    assert ds_code == "DirectoryDoesNotExistException", (
        f"ds DescribeDirectoryDataAccess({absent}) must raise DirectoryDoesNotExistException -- "
        f"the control plane DOES disclose non-existence -- got {ds_code!r}"
    )
    # ds appends the call's own RequestId to the message.
    assert ds_message == f"Directory: '{absent}' does not exist. : RequestId: {ds_request_id}", (
        f"ds must name the directory and state that it does not exist, got {ds_message!r}"
    )
    assert ds_status == 400, (
        f"ds reports a missing directory as a 400, where ds-data reports the same id as a 403; "
        f"got {ds_status!r}"
    )
    assert ds_reason is None, (
        f"ds carries no Reason discriminator -- that member exists only in the ds-data model -- "
        f"got {ds_reason!r}"
    )
    assert ds_code != envelopes["list_users"][0], (
        f"the two APIs must not answer the same absent DirectoryId with one code, both said "
        f"{ds_code!r}"
    )

    # Positive control: ds is healthy and the id really is absent, so the refusals are about ds-data.
    inventory = _owned_directory_ids(ds)
    assert absent not in inventory, (
        f"the id used above must be genuinely unissued, but {absent} is in the account inventory "
        f"{sorted(inventory)}"
    )
    limits = ds.get_directory_limits()
    assert isinstance(limits.get("DirectoryLimits"), dict), (
        f"ds GetDirectoryLimits must still succeed after the ds-data refusals, got {limits!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
