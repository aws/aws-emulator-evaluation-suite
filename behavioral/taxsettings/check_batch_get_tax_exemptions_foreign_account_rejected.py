"""batch-get-tax-exemptions-foreign-account-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-tax-exemptions-foreign-account-rejected"
GROUP = "overly-permissive"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetTaxExemptions for the caller's account and a foreign account lists only the foreign account in
    failedAccounts and returns exemption details only for the caller's account, alone or in the mixed request."""
    ts = ctx.client("taxsettings")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    foreign_account_id = "999999999999" if account_id != "999999999999" else "888888888888"

    # AWS serves the mixed-tenant request partially: the foreign account is
    # listed in failedAccounts and the caller's own account is served.
    resp = ts.batch_get_tax_exemptions(accountIds=[account_id, foreign_account_id])
    failed = resp.get("failedAccounts", [])
    exemption_map = resp.get("taxExemptionDetailsMap", {})
    assert failed == [foreign_account_id], (
        f"foreign account not rejected via failedAccounts: failed={failed!r}"
    )
    assert foreign_account_id not in exemption_map, (
        f"foreign account leaked real data into taxExemptionDetailsMap: "
        f"map_keys={list(exemption_map)!r}"
    )
    assert account_id in exemption_map, (
        f"own account missing from taxExemptionDetailsMap in the very same request "
        f"that rejected the foreign account: map_keys={list(exemption_map)!r}"
    )

    # Positive control: scoping the request to only the caller's own account
    # never puts that account in failedAccounts, and is served real data in
    # taxExemptionDetailsMap -- proving the operation itself works and the
    # isolation above is about the foreign account, not a globally broken call.
    resp2 = ts.batch_get_tax_exemptions(accountIds=[account_id])
    assert account_id not in resp2.get("failedAccounts", []), (
        f"own account unexpectedly in failedAccounts for a solo request: {resp2.get('failedAccounts')!r}"
    )
    assert account_id in resp2.get("taxExemptionDetailsMap", {}), (
        f"own account missing from taxExemptionDetailsMap for a solo request: "
        f"map_keys={list(resp2.get('taxExemptionDetailsMap', {}))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
