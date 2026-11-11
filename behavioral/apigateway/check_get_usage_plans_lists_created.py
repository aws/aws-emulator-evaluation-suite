"""get-usage-plans-lists-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-usage-plans-lists-created"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A usage plan created via CreateUsagePlan is enumerable via GetUsagePlans with its throttle/quota
    intact, and once DeleteUsagePlan removes it, GetUsagePlan on the same id fails NotFoundException."""
    apigw = ctx.client("apigateway")
    plan_name = ctx.unique_name("sim2real-usageplan-")
    plan_id = apigw.create_usage_plan(
        name=plan_name,
        description="sim2real behavioral check",
        throttle={"burstLimit": 5, "rateLimit": 10.0},
        quota={"limit": 1000, "period": "MONTH"},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_usage_plan(usagePlanId=plan_id)))

    found = _find_plan(apigw, plan_id)
    assert found is not None, f"usage plan {plan_id} not found via GetUsagePlans pagination"
    assert found["name"] == plan_name, f"expected name {plan_name}, got {found['name']}"
    assert found["throttle"]["burstLimit"] == 5, found["throttle"]
    assert found["throttle"]["rateLimit"] == 10.0, found["throttle"]
    assert found["quota"]["limit"] == 1000, found["quota"]
    assert found["quota"]["period"] == "MONTH", found["quota"]

    apigw.delete_usage_plan(usagePlanId=plan_id)
    code, message = _error(lambda: apigw.get_usage_plan(usagePlanId=plan_id))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "Invalid Usage Plan ID specified", f"unexpected message {message!r}"
    assert _find_plan(apigw, plan_id) is None, f"deleted plan {plan_id} still enumerable via GetUsagePlans"


def _find_plan(apigw, plan_id):
    position = None
    while True:
        kwargs = {"position": position} if position else {}
        resp = apigw.get_usage_plans(**kwargs)
        for item in resp["items"]:
            if item["id"] == plan_id:
                return item
        position = resp.get("position")
        if not position:
            return None


def _error(fn):
    """Call fn(); return the ClientError's (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
