"""usage-plan-negative-quota-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "usage-plan-negative-quota-limit-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlan with a negative quota limit is rejected and never persisted."""
    apigw = ctx.client("apigateway")

    bad_plan_name = ctx.unique_name("sim2real-behav-badplan-")
    err = _client_error(
        lambda: apigw.create_usage_plan(
            name=bad_plan_name, quota={"limit": -5, "period": "DAY"}
        )
    )
    expected = ("BadRequestException", "Usage Plan quota limit must be a non-negative numeric")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected!r}, got {err!r}"

    # Effect absent: no usage plan with that name exists anywhere in the account.
    all_names = set()
    paginator_kwargs = {}
    for _ in range(200):  # safety cap against unbounded pagination
        page = apigw.get_usage_plans(**paginator_kwargs)
        all_names.update(p["name"] for p in page.get("items", []))
        position = page.get("position")
        if not position:
            break
        paginator_kwargs["position"] = position
    assert bad_plan_name not in all_names, all_names

    # Positive control: a valid quota on a separate usage plan succeeds.
    good_plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-goodplan-"), quota={"limit": 100, "period": "DAY"}
    )
    plan_id = good_plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))
    got = apigw.get_usage_plan(usagePlanId=plan_id)
    assert got["quota"]["limit"] == 100, got["quota"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
