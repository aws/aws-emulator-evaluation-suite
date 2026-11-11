"""create-usage-plan-key-invalid-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-usage-plan-key-invalid-type-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlanKey with an unsupported keyType is rejected and associates no key."""
    apigw = ctx.client("apigateway")

    key_name = ctx.unique_name("sim2real-apikey-")
    key_id = apigw.create_api_key(
        name=key_name, enabled=True, tags={"sim2real": "usage-plan-key-invalid-type-rejected"}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-usageplan-"),
        tags={"sim2real": "usage-plan-key-invalid-type-rejected"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    code, message = _error(
        lambda: apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="NOT_A_TYPE")
    )
    assert code == "BadRequestException", f"expected BadRequestException for invalid keyType, got {code}"
    expected = "Invalid Usage Plan key type specified. Must be one of [API_KEY]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    items = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert items == [], f"rejected CreateUsagePlanKey must not associate any key, found {items}"

    # Positive control: the same key with a valid keyType associates successfully.
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    items_after = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert [i["id"] for i in items_after] == [key_id], (
        f"expected the valid keyType association to succeed and be visible, got {items_after}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
