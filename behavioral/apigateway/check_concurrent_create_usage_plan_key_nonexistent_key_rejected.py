"""concurrent-create-usage-plan-key-nonexistent-key-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-usage-plan-key-nonexistent-key-rejected"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateUsagePlanKey calls referencing a keyId that doesn't exist are all
    rejected with NotFoundException, and none leaves a phantom association behind."""
    apigw = ctx.client("apigateway")

    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-plan-"),
        tags={"sim2real": "concurrent-create-usage-plan-key-nonexistent-key-rejected"},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    bogus_key_id = ctx.unique_name("sim2real-nonexistent-key-")

    n_racers = 5

    def _associate(_i: int) -> tuple[str, str | None] | None:
        try:
            apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=bogus_key_id, keyType="API_KEY")
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        outcomes = list(pool.map(_associate, range(n_racers)))

    successes = [o for o in outcomes if o is None]
    assert not successes, (
        "a usage plan key referencing a non-existent API key must never be allowed to "
        f"associate, under any concurrency; outcomes={outcomes}"
    )
    for code, message in outcomes:
        assert code == "NotFoundException", f"expected NotFoundException for missing keyId, got {code}"
        assert message == "Invalid API Key identifier specified", message

    remaining = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert remaining == [], f"a racer left a phantom association behind: {remaining}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
