"""usage-plan-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "usage-plan-lifecycle"
GROUP = 'usage-plans'
SERVICES = ['apigateway']


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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlan -> GetUsagePlan reflects fields -> UpdateUsagePlan's patch is
    reflected -> DeleteUsagePlan removes it, and a further mutation on the dead id
    also 404s (not just a read)."""
    ag = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-apigw-plan-")
    created = ag.create_usage_plan(
        name=name, throttle={"rateLimit": 10.0, "burstLimit": 20}
    )
    plan_id = created["id"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: ag.delete_usage_plan(usagePlanId=plan_id)))

    got = ag.get_usage_plan(usagePlanId=plan_id)
    assert got["name"] == name, f"expected name {name!r}, got {got.get('name')!r}"

    updated = ag.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "sim2real-updated"}],
    )
    assert updated["description"] == "sim2real-updated", (
        f"expected UpdateUsagePlan to echo the new description, got {updated.get('description')!r}"
    )
    got_after_update = ag.get_usage_plan(usagePlanId=plan_id)
    assert got_after_update["description"] == "sim2real-updated", (
        f"expected GetUsagePlan to reflect the patched description, got {got_after_update.get('description')!r}"
    )

    ag.delete_usage_plan(usagePlanId=plan_id)
    err = _client_error(lambda: ag.get_usage_plan(usagePlanId=plan_id))
    assert (err.get("Code"), err.get("Message")) == ("NotFoundException", "Invalid Usage Plan ID specified"), (
        f"expected NotFoundException reading a deleted plan, got {err!r}"
    )

    err = _client_error(
        lambda: ag.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "replace", "path": "/description", "value": "sim2real-dead"}],
        )
    )
    assert (err.get("Code"), err.get("Message")) == ("NotFoundException", "Invalid Usage Plan ID specified"), (
        f"expected UpdateUsagePlan on a deleted plan to 404, got {err!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
