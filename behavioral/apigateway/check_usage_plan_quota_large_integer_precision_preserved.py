"""usage-plan-quota-large-integer-precision-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "usage-plan-quota-large-integer-precision-preserved"
GROUP = "state-machine"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(fn) -> None:
    """Teardown for a resource the check may already have deleted: only NotFoundException is absorbed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Large integer quota/throttle values on a usage plan are preserved with exact numeric
    precision (no float truncation/rounding) across create and get."""
    apigw = ctx.client("apigateway")

    large_limit = 2_000_000_000  # near int32 max; a common float64-vs-int truncation trap
    large_offset = 27  # offset must be between 0 and 27 inclusive (empirically, real AWS)
    burst_limit = 2_000_000_00  # 200,000,000 -- exercises large integer throttle burst too

    created = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-"),
        quota={"limit": large_limit, "offset": large_offset, "period": "MONTH"},
        throttle={"burstLimit": burst_limit, "rateLimit": 12345.6789},
        tags={"sim2real": CHECK},
    )
    plan_id = created["id"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: apigw.delete_usage_plan(usagePlanId=plan_id)))

    got = apigw.get_usage_plan(usagePlanId=plan_id)
    assert got["quota"]["limit"] == large_limit, (
        f"quota limit drifted: sent={large_limit} got={got['quota']['limit']!r}"
    )
    assert isinstance(got["quota"]["limit"], int), (
        f"quota limit was not returned as an exact integer: {got['quota']['limit']!r}"
    )
    assert got["quota"]["offset"] == large_offset, (
        f"quota offset drifted: sent={large_offset} got={got['quota']['offset']!r}"
    )
    assert got["quota"]["period"] == "MONTH", (
        f"quota period changed: got={got['quota']['period']!r}"
    )
    assert got["throttle"]["burstLimit"] == burst_limit, (
        f"throttle burstLimit drifted: sent={burst_limit} got={got['throttle']['burstLimit']!r}"
    )
    assert isinstance(got["throttle"]["burstLimit"], int), (
        f"throttle burstLimit was not returned as an exact integer: {got['throttle']['burstLimit']!r}"
    )
    assert got["throttle"]["rateLimit"] == 12345.6789, (
        f"throttle rateLimit drifted: got={got['throttle']['rateLimit']!r}"
    )

    apigw.delete_usage_plan(usagePlanId=plan_id)
    err = _client_error(lambda: apigw.get_usage_plan(usagePlanId=plan_id))
    assert (err.get("Code"), err.get("Message")) == ("NotFoundException", "Invalid Usage Plan ID specified"), (
        f"expected NotFoundException reading the deleted plan, got {err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
