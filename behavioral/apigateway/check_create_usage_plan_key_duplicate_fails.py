"""create-usage-plan-key-duplicate-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-usage-plan-key-duplicate-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Adding the same API key to a usage plan twice fails with ConflictException and creates no
    duplicate, and once the association is removed the identical call succeeds."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-plan-"),
        tags={"sim2real": "usage-plan-key-duplicate-fails"},
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_usage_plan(usagePlanId=plan_id)))

    key_id = apigw.create_api_key(
        name=ctx.unique_name("sim2real-key-"),
        enabled=True,
        tags={"sim2real": "usage-plan-key-duplicate-fails"},
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_api_key(apiKey=key_id)))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(
        lambda: _safe(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    )

    code, message = _error(
        lambda: apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    )
    assert code == "ConflictException", (
        f"expected ConflictException adding a duplicate usage plan key, got {code!r}"
    )
    expected = "API Key is already subscribed to Usage Plan"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    keys = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert len(keys) == 1, "duplicate usage plan key must not create a second association"

    # restore: remove the association that was forbidding re-creation, then reissue
    # the identical call and demand it now succeeds.
    apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    code_after_delete, message_after_delete = _error(
        lambda: apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    )
    assert code_after_delete == "NotFoundException", (
        f"expected the association to be gone after delete, got {code_after_delete!r}"
    )
    expected = "Invalid Usage Plan ID specified"
    assert message_after_delete == expected, (
        f"expected message {expected!r}, got {message_after_delete!r}"
    )

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    restored = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert len(restored) == 1 and restored[0]["id"] == key_id, (
        f"expected the identical call to re-associate the key after removal, got {restored!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so
    accepted input is reported as accepted rather than as a wrong error code."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
