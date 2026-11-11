"""concurrent-create-usage-plan-key-same-key-dedup."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-usage-plan-key-same-key-dedup"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two parallel CreateUsagePlanKey calls for the same key/plan pair never produce duplicates.

    Exactly one racer succeeds, the other gets ConflictException, and one association remains.
    """
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-raceplan-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key_id = apigw.create_api_key(
        name=ctx.unique_name("sim2real-racekey-"), enabled=True, tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))
    ctx.on_cleanup(lambda: _best_effort_delete_usage_plan_key(apigw, plan_id, key_id))

    def _racer():
        try:
            resp = apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
            return ("ok", resp["id"], None)
        except ClientError as e:
            return ("err", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_racer) for _ in range(2)]
        results = [f.result() for f in futures]

    for outcome, value, message in results:
        if outcome != "ok":
            assert value == "ConflictException", f"unexpected racer outcome: {outcome}, {value}"
            assert message == "API Key is already subscribed to Usage Plan", message
    ok_results = [value for outcome, value, _ in results if outcome == "ok"]
    assert len(ok_results) == 1, f"expected exactly one racer to win, got: {results}"
    assert ok_results[0] == key_id, f"winning racer should return the key id: {ok_results}"

    items = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    matching = [item for item in items if item["id"] == key_id]
    assert len(matching) == 1, f"expected exactly one association, got {len(matching)}: {matching}"

    single = apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    assert single["id"] == key_id, f"independent single-key read disagrees: {single}"




def _best_effort_delete_usage_plan_key(apigw, plan_id: str, key_id: str) -> None:
    try:
        apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
