"""batch-get-tax-exemptions-own-account-accessible."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-tax-exemptions-own-account-accessible"
GROUP = "state"
SERVICES = ["taxsettings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetTaxExemptions always recognizes the caller's own account as
    accessible: it must never appear in the response's failedAccounts list,
    regardless of whether that account currently has any active exemptions."""
    ts = ctx.client("taxsettings")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resp = ts.batch_get_tax_exemptions(accountIds=[account_id])
    failed = resp.get("failedAccounts", [])
    details = resp.get("taxExemptionDetailsMap", {})

    assert account_id not in failed, f"own account unexpectedly in failedAccounts: {failed!r}"
    assert account_id in details, (
        f"own account missing from taxExemptionDetailsMap despite not being in "
        f"failedAccounts: keys={list(details)!r}"
    )
    assert isinstance(details[account_id].get("taxExemptions"), list), (
        f"own account's tax exemption entry has no taxExemptions list: {details[account_id]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
