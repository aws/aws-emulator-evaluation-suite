"""update-usage-plan-invalid-quota-period-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-usage-plan-invalid-quota-period-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUsagePlan rejects an invalid quota period enum value; a valid period patch still succeeds."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-bh-plan-"),
        quota={"limit": 100, "period": "WEEK"},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    # Positive control: a valid enum value (period WEEK -> MONTH) is accepted.
    control = apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[{"op": "replace", "path": "/quota/period", "value": "MONTH"}],
    )
    assert control["quota"]["period"] == "MONTH", f"expected period MONTH, got {control['quota']['period']!r}"

    # Negative: "FORTNIGHT" is not one of the supported enum values (DAY|WEEK|MONTH).
    err = _client_error(
        lambda: apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "replace", "path": "/quota/period", "value": "FORTNIGHT"}],
        )
    )
    assert (err.get("Code"), err.get("Message")) == ('BadRequestException', 'Invalid Usage Plan quota period specified. Must be one of [DAY, WEEK, MONTH]'), (
        f"expected BadRequestException with the quota period message, got {err!r}"
    )

    fetched = apigw.get_usage_plan(usagePlanId=plan_id)
    assert fetched["quota"]["period"] == "MONTH", "rejected patch must not have mutated the quota period"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
