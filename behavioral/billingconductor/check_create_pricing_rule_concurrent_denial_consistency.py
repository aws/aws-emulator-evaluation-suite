"""create-pricing-rule-concurrent-denial-consistency."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "create-pricing-rule-concurrent-denial-consistency"
GROUP = "concurrency"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, 6 concurrent CreatePricingRule calls on one Name all fail with the
    payer-only AccessDeniedException and none succeeds; ListPricingRules fails with the matching denial."""
    from botocore.exceptions import ClientError

    bc = ctx.client("billingconductor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-bc-race-")
    racers = 6

    def _attempt(i: int):
        try:
            arn = bc.create_pricing_rule(
                Name=name,
                Scope="GLOBAL",
                Type="MARKUP",
                ModifierPercentage=float(i + 1),
            )["Arn"]
            return ("ok", arn)
        except ClientError as exc:
            err = exc.response["Error"]
            return ("error", err["Code"], err.get("Message") or "")

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_attempt, i) for i in range(racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]
    if successes:
        winner_arn = successes[0][1]
        ctx.on_cleanup(lambda: bc.delete_pricing_rule(Arn=winner_arn))

    assert successes == [], f"expected zero winners on a non-payer account, got {successes}"
    assert len(results) == racers, f"expected {racers} results, got {len(results)}: {results}"
    assert all(code == "AccessDeniedException" for _, code, _ in errors), (
        f"expected every racer denied with AccessDeniedException, got {errors}"
    )
    expected = f"Account {account_id} is not authorized to call CreatePricingRule. Only payer account is authorized"
    assert all(msg == expected for _, _, msg in errors), (
        f"expected every denial to read {expected!r}, got {errors}"
    )

    try:
        bc.list_pricing_rules(MaxResults=1)
        raise AssertionError("expected ListPricingRules to also be denied on a non-payer account")
    except ClientError as exc:
        list_err = exc.response["Error"]
    list_msg = list_err.get("Message") or ""
    assert list_err["Code"] == "AccessDeniedException", (
        f"expected ListPricingRules denied with AccessDeniedException, got {list_err}"
    )
    expected_list = f"Account {account_id} is not authorized to call ListPricingRules. Only payer account is authorized"
    assert list_msg == expected_list, (
        f"expected the ListPricingRules denial to read {expected_list!r}, got {list_err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
