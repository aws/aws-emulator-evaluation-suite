"""get-usage-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-usage-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of its ClientError. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected GetUsage to reject this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUsage on a real usagePlanId succeeds (positive control); GetUsage on a
    usagePlanId that does not exist returns NotFoundException."""
    ag = ctx.client("apigateway")
    plan_id = ag.create_usage_plan(name=ctx.unique_name("sim2real-behav-plan-"))["id"]
    ctx.on_cleanup(lambda: ag.delete_usage_plan(usagePlanId=plan_id))

    start_date, end_date = "2024-01-01", "2024-01-31"

    control = ag.get_usage(usagePlanId=plan_id, startDate=start_date, endDate=end_date)
    assert control.get("usagePlanId") == plan_id, (
        f"positive control: expected GetUsage on the freshly created plan {plan_id!r} "
        f"to succeed and echo its id, got {control!r}"
    )

    code, message = _error(
        lambda: ag.get_usage(
            usagePlanId="sim2realNOTFOUND",
            startDate=start_date,
            endDate=end_date,
        )
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException for an unknown usagePlanId, got {code}"
    )
    assert message == "Invalid Usage Plan ID specified", f"unexpected message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
