"""usage-plan-quota-unknown-key-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "usage-plan-quota-unknown-key-rejected"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateUsage/GetUsage reject a keyId that does not correspond to any real API key,
    and leave the plan's actual, associated key untouched."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-quota-unknown-plan-"),
        quota={"limit": 5, "period": "DAY"},
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    associated_key_id = apigw.create_api_key(
        name=ctx.unique_name("sim2real-quota-assoc-key-"), enabled=True, tags={"sim2real-check": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=associated_key_id))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=associated_key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=associated_key_id))

    unknown_key_id = ctx.unique_name("sim2real-nonexistent-key-")

    today = dt.datetime.utcnow().strftime("%Y-%m-%d")

    # Baseline: a valid remaining-quota value for the real, associated key.
    apigw.update_usage(
        usagePlanId=plan_id,
        keyId=associated_key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "3"}],
    )

    err = _client_error(
        lambda: apigw.update_usage(
            usagePlanId=plan_id,
            keyId=unknown_key_id,
            patchOperations=[{"op": "replace", "path": "/remaining", "value": "1"}],
        )
    )
    expected = ("NotFoundException", "Invalid API Key content specified")
    assert (err.get("Code"), err.get("Message")) == expected, (
        f"expected {expected!r} for a keyId that doesn't exist, got {err!r}"
    )

    err = _client_error(
        lambda: apigw.get_usage(usagePlanId=plan_id, keyId=unknown_key_id, startDate=today, endDate=today)
    )
    expected = ("NotFoundException", "Invalid Key identifier specified")
    assert (err.get("Code"), err.get("Message")) == expected, (
        f"expected GetUsage to also reject the nonexistent key with {expected!r}, got {err!r}"
    )

    # The real, associated key's usage is unaffected by the rejected attempts on the unknown key.
    usage = apigw.get_usage(usagePlanId=plan_id, keyId=associated_key_id, startDate=today, endDate=today)
    _used, remaining = usage["items"][associated_key_id][-1]
    assert remaining == 3, f"the associated key's usage must be unaffected, got remaining={remaining}"


def _client_error(fn):
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
