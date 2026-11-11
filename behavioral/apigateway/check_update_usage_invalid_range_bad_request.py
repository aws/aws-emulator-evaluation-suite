"""update-usage-invalid-range-bad-request."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-usage-invalid-range-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not be reported as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a valid UpdateUsage, GetUsage for the same plan and key succeeds for an in-bounds date
    range (positive control) and fails with BadRequestException for a range beyond the documented
    90-day maximum."""
    apigw = ctx.client("apigateway")
    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-plan-"),
        quota={"limit": 1000, "period": "MONTH"},
        throttle={"burstLimit": 10, "rateLimit": 5.0},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key = apigw.create_api_key(name=ctx.unique_name("sim2real-behav-key-"), enabled=True)
    key_id = key["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    # valid: grant a temporary remaining-quota extension for this key
    updated = apigw.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "10"}],
    )
    assert updated["usagePlanId"] == plan_id, (
        f"expected UpdateUsage to echo usagePlanId {plan_id!r}, got {updated.get('usagePlanId')!r}"
    )

    # positive control: GetUsage with a valid, in-bounds date range succeeds for this
    # same usagePlanId/keyId pair, so the negative below is known to test the range
    # itself rather than GetUsage being broken or unreachable for this plan.
    today = dt.date.today()
    valid_start = (today - dt.timedelta(days=1)).isoformat()
    valid_end = today.isoformat()
    valid_report = apigw.get_usage(
        usagePlanId=plan_id, keyId=key_id, startDate=valid_start, endDate=valid_end
    )
    assert valid_report["usagePlanId"] == plan_id, (
        f"expected in-range GetUsage to succeed and echo usagePlanId {plan_id!r}, "
        f"got {valid_report.get('usagePlanId')!r}"
    )

    # invalid: date range spanning more than the documented 90-day maximum
    start = (today - dt.timedelta(days=400)).isoformat()
    end = today.isoformat()
    err = _client_error(
        lambda: apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=start, endDate=end)
    )
    assert (err.get("Code"), err.get("Message")) == ('BadRequestException', 'Usage date range cannot exceed 90 days'), (
        f"expected BadRequestException with the 90-day range message, got {err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
