"""op-contract-getUsagePlanKey."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-getUsagePlanKey"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUsagePlanKey returns the associated API key's identity and NotFoundException for a real
    key never associated with the plan; after the association is deleted, both the read and a
    second delete of it return NotFoundException."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(name=ctx.unique_name("sim2real-plan-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key_name = ctx.unique_name("sim2real-key-")
    key = apigw.create_api_key(name=key_name, enabled=True, tags={"sim2real": CHECK})
    key_id = key["id"]
    key_value = key["value"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    other_key = apigw.create_api_key(
        name=ctx.unique_name("sim2real-key-unassoc-"), enabled=True, tags={"sim2real": CHECK}
    )
    other_key_id = other_key["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=other_key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: _delete_usage_plan_key_if_present(apigw, plan_id, key_id))

    got = apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    assert got["id"] == key_id, f"expected id {key_id!r}, got {got['id']!r}"
    assert got["name"] == key_name, f"expected name {key_name!r}, got {got['name']!r}"
    assert got["value"] == key_value, f"expected value {key_value!r}, got {got['value']!r}"
    assert got["type"] == "API_KEY", f"expected type 'API_KEY', got {got['type']!r}"

    code, message = _error(lambda: apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=other_key_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == (
        'Invalid Usage Plan ID specified'
    ), f"unexpected {code} message: {message!r}"

    # After the delete the association is both gone (independent read) and unusable (a repeat
    # delete also fails).
    apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    gone_code, gone_code_message = _error(lambda: apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    assert gone_code == "NotFoundException", f"expected NotFoundException after delete, got {gone_code}"
    assert gone_code_message == (
        'Invalid Usage Plan ID specified'
    ), f"unexpected {gone_code} message: {gone_code_message!r}"

    redelete_code, redelete_code_message = _error(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    assert redelete_code == "NotFoundException", (
        f"expected NotFoundException deleting an already-deleted association, got {redelete_code}"
    )
    assert redelete_code_message == (
        'Invalid Usage Plan ID specified'
    ), f"unexpected {redelete_code} message: {redelete_code_message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_usage_plan_key_if_present(apigw, plan_id, key_id):
    from botocore.exceptions import ClientError

    try:
        apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
