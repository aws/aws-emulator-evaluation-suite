"""concurrent-delete-usage-plan-key-double-delete-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-usage-plan-key-double-delete-rejected"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing DeleteUsagePlanKey calls for the same association: exactly one wins, rest 404."""
    apigw = ctx.client("apigateway")

    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-plan-"), tags={"sim2real": "true"}
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key = apigw.create_api_key(
        name=ctx.unique_name("sim2real-behav-key-"), enabled=True, tags={"sim2real": "true"}
    )
    key_id = key["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")

    n_racers = 6

    def _delete(_i: int) -> tuple | None:
        try:
            apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        outcomes = list(pool.map(_delete, range(n_racers)))

    successes = [o for o in outcomes if o is None]
    failures = [o for o in outcomes if o is not None]
    assert len(successes) == 1, f"exactly one racer should win the delete, got outcomes={outcomes}"
    assert len(failures) == n_racers - 1, f"expected {n_racers - 1} losing racers, got outcomes={outcomes}"
    for code, message in failures:
        assert code == "NotFoundException", f"expected NotFoundException on re-delete, got {code}"
        assert message == "Invalid Usage Plan ID specified", f"unexpected message {message!r}"

    # the association must actually be gone, not merely reporting so inconsistently
    remaining = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert remaining == [], f"usage plan key association still present after delete race: {remaining}"

    # a delete after the fact against the now-cleared plan must also 404, never silently succeed
    _assert_not_found(apigw, plan_id, key_id)


def _assert_not_found(apigw: Any, plan_id: str, key_id: str) -> None:
    try:
        apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "NotFoundException", f"expected NotFoundException, got {code}"
        assert message == "Invalid Usage Plan ID specified", f"unexpected message {message!r}"
    else:
        raise AssertionError("deleting an already-deleted usage plan key association must fail")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
