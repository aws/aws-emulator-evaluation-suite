"""create-member-self-account-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-member-self-account-rejected"
GROUP = "overly-permissive"
SERVICES = ["macie2"]
_DOC_ACCOUNT = "444455556666"  # an AWS documentation account id: it names no real account


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """CreateMember rejects an attempt to add the caller's own account as a Macie member."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    own_account = ctx.client("sts").get_caller_identity()["Account"]

    error = _client_error(
        lambda: macie.create_member(account={"accountId": own_account, "email": "self@example.com"})
    )
    assert error["Code"] == "ValidationException", f"unexpected code: {error['Code']}"
    assert error["Message"] == (
        "The request is rejected because an account cannot become a member of itself."
    ), f"unexpected message: {error['Message']!r}"

    # Effect must be absent: the caller's own account never appears as a member of itself.
    own_lookup = _client_error(lambda: macie.get_member(id=own_account))
    assert own_lookup["Code"] == "ValidationException", f"unexpected code: {own_lookup['Code']}"
    assert own_lookup["Message"] == (
        "The request is rejected because the given account ID is not an associated member of the current account."
    ), f"unexpected message: {own_lookup['Message']!r}"

    # Positive control: adding a genuinely different account succeeds.
    other_account = _DOC_ACCOUNT
    if any(m["accountId"] == other_account for m in macie.list_members(onlyAssociated="false")["members"]):
        macie.delete_member(id=other_account)  # an interrupted run left this fixed id a member
    macie.create_member(
        account={"accountId": other_account, "email": "sim2real-behav@example.com"},
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: macie.delete_member(id=other_account))
    member = macie.get_member(id=other_account)
    assert member["accountId"] == other_account, f"expected accountId {other_account}, got {member.get('accountId')}"


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
