"""create-usage-plan-key-wrong-type-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-usage-plan-key-wrong-type-fails"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlanKey with a keyType other than API_KEY must fail, associate no key,
    and the same key must associate normally once keyType is corrected (overly-permissive check)."""
    ag = ctx.client("apigateway")
    plan = ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-apigw-badkeytype-"),
        tags={"sim2real": CHECK},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: ag.delete_usage_plan(usagePlanId=plan_id))
    key = ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-apigw-badkeytype-apikey-"),
        tags={"sim2real": CHECK},
    )
    key_id = key["id"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=key_id))

    code, message = _error(
        lambda: ag.create_usage_plan_key(
            usagePlanId=plan_id, keyId=key_id, keyType="NOT_API_KEY"
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = "Invalid Usage Plan key type specified. Must be one of [API_KEY]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    items = ag.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert items == [], f"rejected CreateUsagePlanKey must not associate any key, found {items}"

    # Positive control: the identical call with the valid keyType succeeds and is
    # visible at an independent read, proving the rejection above targeted the
    # keyType value and not the plan/key themselves.
    ag.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: ag.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    items_after = ag.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert [i["id"] for i in items_after] == [key_id], (
        f"expected key {key_id} associated after valid keyType, found {items_after}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
