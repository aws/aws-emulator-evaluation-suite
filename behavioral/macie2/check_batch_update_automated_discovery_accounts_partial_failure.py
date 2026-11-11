"""batch-update-automated-discovery-accounts-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-update-automated-discovery-accounts-partial-failure"
GROUP = "data-plane"
SERVICES = ["macie2"]
_DOC_ACCOUNT = "444455556666"  # an AWS documentation account id: it names no real account


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """BatchUpdateAutomatedDiscoveryAccounts returns ACCOUNT_NOT_FOUND for an unknown account in its
    errors list while flipping the administrator's own account in the same call.
    """
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    _ensure_automated_discovery_enabled(macie)
    own_account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_account = _DOC_ACCOUNT

    original_status = macie.list_automated_discovery_accounts(accountIds=[own_account])["items"][0]["status"]
    target_status = "DISABLED" if original_status == "ENABLED" else "ENABLED"
    ctx.on_cleanup(lambda: _restore_own_account_status(macie, own_account, original_status))

    # bogus_account was never registered with Macie at all, so per-account processing must fail for
    # it -- but the call itself must not raise, and own_account must succeed in the very same batch.
    # Right after enabling automated discovery, the org-wide auto-enable rollout can transiently
    # reject any BatchUpdateAutomatedDiscoveryAccounts call with ConflictException; retry through
    # that bounded settling window.
    resp = _batch_update_with_retry(macie, [
        {"accountId": own_account, "status": target_status},
        {"accountId": bogus_account, "status": target_status},
    ])

    errors = resp.get("errors", [])
    assert len(errors) == 1, f"expected exactly one per-account error, got {errors}"
    assert errors[0]["accountId"] == bogus_account, (
        f"error attributed to {errors[0]['accountId']!r}, expected the unregistered {bogus_account!r}"
    )
    assert errors[0]["errorCode"] == "ACCOUNT_NOT_FOUND", f"unexpected errorCode: {errors[0]['errorCode']!r}"

    # Independent read at the destination (ListAutomatedDiscoveryAccounts, not the mutating call's
    # own response): own_account's status genuinely flipped, and bogus_account never appears at all.
    listed = macie.list_automated_discovery_accounts(accountIds=[own_account, bogus_account])["items"]
    by_id = {item["accountId"]: item["status"] for item in listed}
    assert by_id.get(own_account) == target_status, f"own_account status not updated: {by_id}"
    assert bogus_account not in by_id, f"unregistered bogus_account unexpectedly listed: {by_id}"


def _restore_own_account_status(macie, own_account, original_status) -> None:
    _batch_update_with_retry(macie, [{"accountId": own_account, "status": original_status}])


def _batch_update_with_retry(macie, accounts):
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return macie.batch_update_automated_discovery_accounts(accounts=accounts)
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] == "ConflictException" and "auto-enabl" in msg:
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"batch_update_automated_discovery_accounts still conflicting: {last_exc}")


def _ensure_automated_discovery_enabled(macie) -> None:
    import time
    from botocore.exceptions import ClientError

    try:
        current = macie.get_automated_discovery_configuration()
    except ClientError:
        current = {}
    if current.get("status") == "ENABLED" and current.get("autoEnableOrganizationMembers") == "NONE":
        return
    # autoEnableOrganizationMembers must be NONE for BatchUpdateAutomatedDiscoveryAccounts to be
    # allowed to manage individual accounts -- ALL/NEW conflicts with per-account control.
    macie.update_automated_discovery_configuration(status="ENABLED", autoEnableOrganizationMembers="NONE")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        cfg = macie.get_automated_discovery_configuration()
        if cfg.get("status") == "ENABLED" and cfg.get("autoEnableOrganizationMembers") == "NONE":
            return
        time.sleep(3)
    raise AssertionError("automated discovery configuration did not settle to ENABLED/NONE in time")


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
