"""account-link-invalid-target-account-id-rejected."""
from __future__ import annotations

import random

from behavioral_harness import tags

CHECK = "account-link-invalid-target-account-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["workspaces"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccountLinkInvitation with a TargetAccountId that is not 12 digits fails with
    ValidationException, and with a well-formed nonexistent account id with AccessDeniedException, each
    with the exact message and no new link listed.
    """
    ws = ctx.client("workspaces")
    source_account = ctx.client("sts").get_caller_identity()["Account"]

    before = {link["AccountLinkId"] for link in ws.list_account_links().get("AccountLinks", [])}

    error = _error(lambda: ws.create_account_link_invitation(TargetAccountId="12345"))
    expected_error = ("ValidationException", "The request is invalid.")
    assert error == expected_error, f"expected {expected_error!r}, got {error!r}"

    after = {link["AccountLinkId"] for link in ws.list_account_links().get("AccountLinks", [])}
    assert after == before, f"a link appeared despite the rejected invitation: {after - before}"

    # Distinct boundary: syntactically valid (12-digit) but non-existent target account id must
    # still be rejected — being well-formed is NOT sufficient for acceptance.
    target_account = _random_target_account_id(exclude=source_account)
    error2 = _error(lambda: ws.create_account_link_invitation(TargetAccountId=target_account))
    expected_error2 = ("AccessDeniedException", (
        "Please ensure both accounts to be linked exist and belong to the same parent AWS Organization."
    ))
    assert error2 == expected_error2, (
        f"expected {expected_error2!r} for a non-existent account, got {error2!r}"
    )

    after2 = {link["AccountLinkId"] for link in ws.list_account_links().get("AccountLinks", [])}
    assert after2 == before, f"a link appeared despite the rejected invitation: {after2 - before}"


def _random_target_account_id(exclude: str) -> str:
    rng = random.Random()
    while True:
        candidate = f"{rng.randint(100000000000, 999999999999)}"
        if candidate != exclude:
            return candidate


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
