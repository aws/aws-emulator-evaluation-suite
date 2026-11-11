"""member-relationship-status-created-then-removed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "member-relationship-status-created-then-removed"
GROUP = "state"
SERVICES = ["macie2"]
_DOC_ACCOUNT = "444455556666"  # an AWS documentation account id: it names no real account


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """CreateMember starts a member at relationshipStatus 'Created'; DeleteMember removes it entirely."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    member_account = _DOC_ACCOUNT

    if any(m["accountId"] == member_account for m in macie.list_members(onlyAssociated="false")["members"]):
        macie.delete_member(id=member_account)  # an interrupted run left this fixed id a member
    macie.create_member(
        account={"accountId": member_account, "email": "sim2real-behav@example.com"},
        tags={"sim2real-behav": "member-relationship-status-created-then-removed"},
    )
    ctx.on_cleanup(lambda: _delete_member_ignore_missing(macie, member_account))

    member = macie.get_member(id=member_account)
    assert member["relationshipStatus"] == "Created", f"expected Created, got {member['relationshipStatus']!r}"
    assert member["accountId"] == member_account, f"expected {member_account}, got {member['accountId']!r}"

    macie.delete_member(id=member_account)

    not_found = _client_error(lambda: macie.get_member(id=member_account))
    assert not_found["Code"] == "ValidationException", f"unexpected code: {not_found['Code']}"
    assert not_found["Message"] == _NOT_A_MEMBER, f"unexpected message: {not_found['Message']!r}"

    # a second delete is a no-op success: a ClientError here fails the check
    macie.delete_member(id=member_account)

    still_gone = _client_error(lambda: macie.get_member(id=member_account))
    assert still_gone["Code"] == "ValidationException", (
        f"a double-deleted member must not have been resurrected, got {still_gone['Code']}"
    )
    assert still_gone["Message"] == _NOT_A_MEMBER, f"unexpected message: {still_gone['Message']!r}"


_NOT_A_MEMBER = (
    "The request is rejected because the given account ID is not an associated member of the current account."
)


def _delete_member_ignore_missing(macie, member_account: str) -> None:
    from botocore.exceptions import ClientError

    try:
        macie.delete_member(id=member_account)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ensure_macie_enabled(ctx) -> None:
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
        try:
            macie.enable_macie()
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] != "ConflictException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
