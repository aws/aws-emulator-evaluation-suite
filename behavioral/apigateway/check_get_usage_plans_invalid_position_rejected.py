"""get-usage-plans-invalid-position-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-usage-plans-invalid-position-rejected"
GROUP = "pagination"
SERVICES = ["apigateway"]

_INVALID_POSITION = ("BadRequestException", "Invalid position parameter")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUsagePlans with an unparseable position token is refused with BadRequestException;
    the plan a prior unfiltered listing found is still listed the same way afterward."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-apigw-plan-"),
        description="behavioral fidelity check",
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    before = apigw.get_usage_plans()
    assert plan_id in {item["id"] for item in before["items"]}, (
        f"expected {plan_id!r} among GetUsagePlans items, got {[i['id'] for i in before['items']]!r}"
    )

    code, message = _error_pair(lambda: apigw.get_usage_plans(position="not-a-real-pagination-token"))
    assert (code, message) == _INVALID_POSITION, f"expected {_INVALID_POSITION}, got {(code, message)}"

    after = apigw.get_usage_plans()
    assert plan_id in {item["id"] for item in after["items"]}, (
        f"expected {plan_id!r} still among GetUsagePlans items after the refused call, "
        f"got {[i['id'] for i in after['items']]!r}"
    )


def _error_pair(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises, so an
    over-permissive target cannot be confused with a message mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
