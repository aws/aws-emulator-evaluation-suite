"""list-members-only-associated-filter-toggle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-members-only-associated-filter-toggle"
GROUP = "state"
SERVICES = ["macie2"]
_DOC_ACCOUNT = "444455556666"  # an AWS documentation account id: it names no real account


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """A member with relationshipStatus 'Created' is excluded by the default (associated-only) ListMembers
    view but included once onlyAssociated is explicitly set to false."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    member_account = _DOC_ACCOUNT

    if any(m["accountId"] == member_account for m in macie.list_members(onlyAssociated="false")["members"]):
        macie.delete_member(id=member_account)  # an interrupted run left this fixed id a member
    macie.create_member(
        account={"accountId": member_account, "email": "sim2real-behav@example.com"},
        tags={"sim2real": "list-members-only-associated-filter-toggle"},
    )
    ctx.on_cleanup(lambda: macie.delete_member(id=member_account))

    member = macie.get_member(id=member_account)
    assert member["relationshipStatus"] == "Created", (
        f"expected new member to be in relationshipStatus 'Created', got {member['relationshipStatus']!r}"
    )

    in_default_view = _find_account_in_members(macie, member_account, only_associated=None)
    assert in_default_view is False, (
        f"expected default (onlyAssociated=true) ListMembers to exclude a 'Created' member "
        f"{member_account}, but it was present"
    )
    in_all_view = _find_account_in_members(macie, member_account, only_associated="false")
    assert in_all_view is True, (
        f"expected ListMembers(onlyAssociated=false) to include 'Created' member {member_account}, "
        f"but it was absent"
    )


def _find_account_in_members(macie, account_id: str, only_associated) -> bool:
    kwargs = {}
    if only_associated is not None:
        kwargs["onlyAssociated"] = only_associated
    next_token = None
    for _ in range(20):
        if next_token:
            kwargs["nextToken"] = next_token
        resp = macie.list_members(**kwargs)
        for member in resp.get("members", []):
            if member["accountId"] == account_id:
                return True
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return False


def _ensure_macie_enabled(ctx) -> None:
    """Enable Macie when the account has no session, and disable it again at cleanup so the
    account-wide setting ends in the state it started in."""
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
    try:
        macie.enable_macie()
    except ClientError as exc2:
        if exc2.response["Error"]["Code"] != "ConflictException":
            raise
        return
    ctx.on_cleanup(macie.disable_macie)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
