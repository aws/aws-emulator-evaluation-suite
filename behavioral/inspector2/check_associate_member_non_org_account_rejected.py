"""associate-member-non-org-account-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "associate-member-non-org-account-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector2"]

# A syntactically valid 12-digit account ID. Real AWS denies AssociateMember with this id and with
# the caller's own account id identically (verified against real AWS): the refusal tracks the
# caller's own delegated-admin status, not anything specific to this id.
_NON_MEMBER_ACCOUNT_ID = "111122223333"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With no delegated administrator on file (GetDelegatedAdminAccount:
    ResourceNotFoundException and its exact message), AssociateMember fails with
    AccessDeniedException and its exact message, and the account is not listed as a member."""
    inspector2 = ctx.client("inspector2")

    # The account's own reported state, not a hardcoded assumption: no delegated administrator is
    # on file for this account's organization.
    admin_code, admin_msg = _error_code(lambda: inspector2.get_delegated_admin_account())
    assert admin_code == "ResourceNotFoundException", (
        f"expected no delegated admin on file, got {admin_code!r}"
    )
    assert admin_msg == "No delegated admin found for caller account.", admin_msg

    # Positive control: the account's Inspector2 wiring and credentials are otherwise healthy —
    # list_members, which does not require delegated-admin status, succeeds.
    resp = inspector2.list_members()
    assert "members" in resp

    code, msg = _error_code(lambda: inspector2.associate_member(accountId=_NON_MEMBER_ACCOUNT_ID))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert msg == "Invoking account does not have access to associate member account", (
        f"expected the delegated-admin refusal message, got {msg!r}"
    )

    # Effect absent: the bogus account never shows up as a member.
    member_ids = {m["accountId"] for m in _all_members(inspector2)}
    assert _NON_MEMBER_ACCOUNT_ID not in member_ids


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected a ClientError, call unexpectedly succeeded")
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")


def _all_members(inspector2):
    items = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_members(**kwargs)
        items.extend(resp.get("members", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
