"""account-link-invitation-pending-state-lifecycle."""
from __future__ import annotations

import random

from behavioral_harness import tags

CHECK = "account-link-invitation-pending-state-lifecycle"
GROUP = "state"
SERVICES = ["workspaces"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccountLinkInvitation to a nonexistent account fails with AccessDeniedException and the exact
    message and lists no new link; GetAccountLink and DeleteAccountLinkInvitation on a fabricated LinkId
    fail with ResourceNotFoundException and the exact message.
    """
    ws = ctx.client("workspaces")
    source_account = ctx.client("sts").get_caller_identity()["Account"]
    target_account = _random_target_account_id(exclude=source_account)

    before = {link["AccountLinkId"] for link in ws.list_account_links().get("AccountLinks", [])}

    # Real AWS enforces that the target account must actually exist (and share the caller's
    # Organization) before any PENDING state is created — creation fails and nothing is added
    # to the link set. The message is asserted too, tight enough to separate this specific
    # account/org-existence rule from a blanket "no permission to call this API at all" denial,
    # which would also surface as AccessDeniedException but for an unrelated reason.
    err = _client_error(lambda: ws.create_account_link_invitation(TargetAccountId=target_account))
    assert err["Code"] == "AccessDeniedException", f"unexpected code: {err['Code']}"
    expected = (
        "Please ensure both accounts to be linked exist and belong to the same parent AWS Organization."
    )
    assert err.get("Message") == expected, f"unexpected message for nonexistent target account: {err.get('Message')!r}"

    after = {link["AccountLinkId"] for link in ws.list_account_links().get("AccountLinks", [])}
    assert after == before, f"a link appeared despite the rejected invitation: {after - before}"

    # A fabricated LinkId (well-formed per the `link-.{8,24}` pattern but never issued) is
    # rejected by lookups/deletes with the specific not-found code and message, not a generic
    # 4xx that would also match a malformed-input rejection.
    fake_link_id = "link-0000000000000000"
    err = _client_error(lambda: ws.get_account_link(LinkId=fake_link_id))
    assert err["Code"] == "ResourceNotFoundException", f"unexpected code for fake LinkId get: {err['Code']}"
    assert err.get("Message") == "Requested AccountLink could not be found.", (
        f"unexpected message for fake LinkId get: {err.get('Message')!r}"
    )

    err = _client_error(lambda: ws.delete_account_link_invitation(LinkId=fake_link_id))
    assert err["Code"] == "ResourceNotFoundException", f"unexpected code for fake LinkId delete: {err['Code']}"
    assert err.get("Message") == "Requested AccountLink could not be found.", (
        f"unexpected message for fake LinkId delete: {err.get('Message')!r}"
    )


def _random_target_account_id(exclude: str) -> str:
    rng = random.Random()
    while True:
        candidate = f"{rng.randint(100000000000, 999999999999)}"
        if candidate != exclude:
            return candidate


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_invitation(ctx, link_id: str) -> None:
    from botocore.exceptions import ClientError

    ws = ctx.client("workspaces")
    try:
        ws.delete_account_link_invitation(LinkId=link_id)
    except ClientError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
