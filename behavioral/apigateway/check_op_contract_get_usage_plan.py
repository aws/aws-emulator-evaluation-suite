"""op-contract-getUsagePlan."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-getUsagePlan"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUsagePlan round-trips the exact throttle and quota settings supplied at
    creation; a lookup of a nonexistent usagePlanId 404s."""
    apigw = ctx.client("apigateway")

    name = ctx.unique_name("sim2real-behav-plan-")
    created = apigw.create_usage_plan(
        name=name,
        throttle={"burstLimit": 10, "rateLimit": 5.0},
        quota={"limit": 1000, "period": "MONTH"},
        tags={"sim2real": "behavioral"},
    )
    plan_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    got = apigw.get_usage_plan(usagePlanId=plan_id)
    assert got["id"] == plan_id, f"expected id {plan_id!r}, got {got['id']!r}"
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["throttle"]["burstLimit"] == 10, f"expected burstLimit 10, got {got['throttle']['burstLimit']!r}"
    assert got["throttle"]["rateLimit"] == 5.0, f"expected rateLimit 5.0, got {got['throttle']['rateLimit']!r}"
    assert got["quota"]["limit"] == 1000, f"expected quota limit 1000, got {got['quota']['limit']!r}"
    assert got["quota"]["period"] == "MONTH", f"expected quota period MONTH, got {got['quota']['period']!r}"

    code, message = _error(lambda: apigw.get_usage_plan(usagePlanId="nonexistent-plan-id"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Usage Plan ID specified", f"unexpected message {message!r}"


def _error(fn):
    """Call fn(); return the ClientError's (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
