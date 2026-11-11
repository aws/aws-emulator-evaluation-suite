"""op-contract-delete-usage-plan-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-usage-plan-key"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUsagePlanKey removes only the targeted API_KEY association with HTTP 202 (GetUsagePlanKey and a
    repeat delete then return NotFoundException while the ApiKey and UsagePlan remain), and deleting a keyId
    never associated with the plan returns NotFoundException, each with its exact message."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(name=ctx.unique_name("sim2real-apigw-plan-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key_name = ctx.unique_name("sim2real-apigw-key-")
    key_id = apigw.create_api_key(name=key_name, enabled=True)["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    positive = apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    assert positive["id"] == key_id, f"expected association readable, got {positive!r}"
    assert positive["type"] == "API_KEY", f"expected type API_KEY, got {positive['type']!r}"
    assert positive["name"] == key_name, f"expected name {key_name!r}, got {positive['name']!r}"

    status = apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 202, f"expected HTTP 202 from DeleteUsagePlanKey, got {status}"
    err = _client_error(lambda: apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    assert err.get("Code") == "NotFoundException", f"expected association gone, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Usage Plan ID specified", (
        f"expected the exact NotFound message from GetUsagePlanKey, got {err.get('Message')!r}"
    )
    # both the ApiKey and the UsagePlan themselves are untouched
    surviving_key = apigw.get_api_key(apiKey=key_id)
    assert surviving_key["id"] == key_id, f"ApiKey must survive the association delete, got {surviving_key!r}"
    surviving_plan = apigw.get_usage_plan(usagePlanId=plan_id)
    assert surviving_plan["id"] == plan_id, f"UsagePlan must survive the association delete, got {surviving_plan!r}"

    # deleting the already-removed association is refused, not accepted as an idempotent no-op
    err_repeat = _client_error(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    assert err_repeat.get("Code") == "NotFoundException", f"expected NotFoundException, got {err_repeat.get('Code')!r}"
    assert err_repeat.get("Message") == "Invalid Usage Plan ID specified", (
        f"expected the exact NotFound message from the repeat DeleteUsagePlanKey, got {err_repeat.get('Message')!r}"
    )

    # error boundary: a keyId never associated with this usagePlanId -> NotFoundException
    err2 = _client_error(
        lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId="nonexistentkey")
    )
    assert err2.get("Code") == "NotFoundException", f"expected NotFoundException, got {err2.get('Code')!r}"
    assert err2.get("Message") == "Invalid API Key identifier specified", (
        f"expected the exact NotFound message from DeleteUsagePlanKey, got {err2.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not be reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
