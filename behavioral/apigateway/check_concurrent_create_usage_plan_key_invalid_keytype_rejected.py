"""concurrent-create-usage-plan-key-invalid-keytype-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-usage-plan-key-invalid-keytype-rejected"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateUsagePlanKey with an invalid keyType are all rejected, never let one slip
    through -- even while a concurrent racer using the valid keyType succeeds on the same pair,
    so the rejection is a real classification and not just every call failing."""
    apigw = ctx.client("apigateway")

    plan = apigw.create_usage_plan(name=ctx.unique_name("sim2real-behav-plan-"))
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key = apigw.create_api_key(name=ctx.unique_name("sim2real-behav-key-"), enabled=True)
    key_id = key["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    n_invalid_racers = 5

    def _associate(key_type: str) -> tuple[str, str | None] | None:
        try:
            apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType=key_type)
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    # one positive-control racer with the valid keyType, racing against n_invalid_racers using an
    # invalid one -- on the same plan/key pair, in the same instant.
    key_types = ["NOT_A_REAL_TYPE"] * n_invalid_racers + ["API_KEY"]
    with ThreadPoolExecutor(max_workers=len(key_types)) as pool:
        outcomes = list(pool.map(_associate, key_types))
    invalid_outcomes, valid_outcome = outcomes[:n_invalid_racers], outcomes[n_invalid_racers]

    assert valid_outcome is None, (
        f"positive control failed: the valid-keyType racer was rejected too (got {valid_outcome}), "
        "so this account/wiring cannot tell an invalid keyType from a healthy one"
    )
    for outcome in invalid_outcomes:
        assert outcome is not None, "an invalid-keyType racer was accepted"
        code, message = outcome
        assert code == "BadRequestException", f"expected BadRequestException for invalid keyType, got {code}"
        assert message == "Invalid Usage Plan key type specified. Must be one of [API_KEY]", message

    # confirm exactly the valid racer's association survived -- no invalid racer slipped through,
    # and the valid one was not collaterally dropped by the race
    remaining = [i["id"] for i in apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]]
    assert remaining == [key_id], f"expected only the valid-keyType association to survive the race, got {remaining}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
