"""concurrent-usage-plan-key-association-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-usage-plan-key-association-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Parallel CreateUsagePlanKey for the same plan+key resolve to a single association."""
    apigw = ctx.client("apigateway")

    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-plan-"),
        tags={"sim2real": "concurrent-usage-plan-key-association-race"},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key = apigw.create_api_key(
        name=ctx.unique_name("sim2real-behav-key-"),
        enabled=True,
        tags={"sim2real": "concurrent-usage-plan-key-association-race"},
    )
    key_id = key["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    n_racers = 6

    def _associate(_i: int) -> tuple[dict[str, Any] | None, str | None, str | None]:
        try:
            resp = apigw.create_usage_plan_key(
                usagePlanId=plan_id, keyId=key_id, keyType="API_KEY"
            )
            return resp, None, None
        except ClientError as exc:
            return None, exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        outcomes = list(pool.map(_associate, range(n_racers)))

    # ensure exactly one association survives regardless of how many racers "succeeded"
    ctx.on_cleanup(lambda: _safe_delete_usage_plan_key(apigw, plan_id, key_id))

    successes = [o for o in outcomes if o[0] is not None]
    failures = [o for o in outcomes if o[1] is not None]
    assert len(successes) == 1, (
        f"expected exactly 1 of {n_racers} racers to win the association, got {len(successes)}: "
        f"outcomes={outcomes}"
    )
    for _, code, message in failures:
        assert code == "ConflictException", f"unexpected error code on duplicate association: {code}"
        assert message == "API Key is already subscribed to Usage Plan", message

    keys = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert len(keys) == 1, f"expected exactly 1 usage plan key association, got {len(keys)}: {keys}"
    assert keys[0]["id"] == key_id, f"expected the surviving association to be {key_id}, got {keys[0]['id']}"

    single = apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    assert single["id"] == key_id, f"expected GetUsagePlanKey to return {key_id}, got {single['id']}"


def _safe_delete_usage_plan_key(apigw: Any, plan_id: str, key_id: str) -> None:
    try:
        apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
