"""batch-get-account-status-non-member-account-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-account-status-non-member-account-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector2"]

# A syntactically valid 12-digit account ID that is not a member of the caller's organization.
_NON_MEMBER_ACCOUNT_ID = "111122223333"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetAccountStatus rejects a request that includes an accountId that isn't a member account."""
    inspector2 = ctx.client("inspector2")
    caller_account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: querying the caller's own account succeeds.
    own = inspector2.batch_get_account_status(accountIds=[caller_account])
    assert len(own["accounts"]) == 1, f"expected exactly 1 account status, got {own['accounts']!r}"
    assert own["accounts"][0]["accountId"] == caller_account, (
        f"expected accountId {caller_account!r}, got {own['accounts'][0]['accountId']!r}"
    )

    # Negative: mixing in an account that is not a member of the organization does not silently
    # succeed as if it were a real member — it is reported per-account in failedAccounts with an
    # error code, rather than appearing in the successful "accounts" list.
    resp = inspector2.batch_get_account_status(
        accountIds=[caller_account, _NON_MEMBER_ACCOUNT_ID]
    )
    succeeded_ids = {a["accountId"] for a in resp.get("accounts", [])}
    assert _NON_MEMBER_ACCOUNT_ID not in succeeded_ids, (
        f"non-member account {_NON_MEMBER_ACCOUNT_ID} unexpectedly returned a real status: {resp}"
    )
    failed_ids = {f["accountId"]: f for f in resp.get("failedAccounts", [])}
    assert _NON_MEMBER_ACCOUNT_ID in failed_ids, (
        f"expected {_NON_MEMBER_ACCOUNT_ID} in failedAccounts, got accounts={succeeded_ids} "
        f"failedAccounts={failed_ids}"
    )
    failed = failed_ids[_NON_MEMBER_ACCOUNT_ID]
    assert failed["errorCode"] == "ACCESS_DENIED", f"unexpected errorCode {failed!r}"
    assert failed["errorMessage"] == "Invoking account does not have access to this account", (
        f"unexpected errorMessage {failed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
