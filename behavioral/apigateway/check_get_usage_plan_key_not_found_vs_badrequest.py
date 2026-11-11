"""get-usage-plan-key-not-found-vs-badrequest."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-usage-plan-key-not-found-vs-badrequest"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUsagePlanKey returns NotFoundException, not BadRequestException, for both an unknown
    keyId on a real usage plan and a malformed usagePlanId: both identifiers are resolved by
    lookup, not by shape validation."""
    apigw = ctx.client("apigateway")
    plan_id = apigw.create_usage_plan(name=ctx.unique_name("sim2real-bhv-plan-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    # Positive control: a real key actually associated with the plan must be readable, so the
    # NotFoundExceptions below cannot be explained by GetUsagePlanKey simply always failing.
    key = apigw.create_api_key(name=ctx.unique_name("sim2real-bhv-key-"), enabled=True, tags={"sim2real": CHECK})
    key_id = key["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: _delete_usage_plan_key_if_present(apigw, plan_id, key_id))
    control = apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    assert control["id"] == key_id, f"expected positive control to return {key_id!r}, got {control['id']!r}"

    # A real usage plan, but a keyId that was never created/associated -> NotFoundException.
    not_found_code, not_found_message = _error(lambda: apigw.get_usage_plan_key(usagePlanId=plan_id, keyId="nonexistentkey000"))
    assert not_found_code == "NotFoundException", f"expected NotFoundException for unknown keyId, got {not_found_code!r}"
    assert not_found_message == "Invalid API Key identifier specified", (
        f"unexpected unknown-keyId message: {not_found_message!r}"
    )

    # A usagePlanId that was never issued (well-formed but does not resolve to any usage plan)
    # is looked up the same way and also yields NotFoundException, not BadRequestException.
    unknown_plan_code, unknown_plan_message = _error(
        lambda: apigw.get_usage_plan_key(usagePlanId="notarealplan0", keyId="nonexistentkey000")
    )
    assert unknown_plan_code == "NotFoundException", (
        f"expected NotFoundException for unknown usagePlanId, got {unknown_plan_code!r}"
    )
    assert unknown_plan_message == "Invalid API Key identifier specified", (
        f"unexpected unknown-usagePlanId message: {unknown_plan_message!r}"
    )

    # A syntactically odd usagePlanId still reaches the service (its Id shape has no pattern or length
    # constraint) and lookup-by-id answers NotFoundException, not BadRequestException.
    malformed_code, malformed_message = _error(
        lambda: apigw.get_usage_plan_key(usagePlanId="not a valid id! #?", keyId="nonexistentkey000")
    )
    assert malformed_code == "NotFoundException", (
        f"expected NotFoundException for a syntactically odd usagePlanId, got {malformed_code!r}"
    )
    assert malformed_message == "Invalid API Key identifier specified", (
        f"unexpected syntactically-odd-usagePlanId message: {malformed_message!r}"
    )


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return botocore (Error.Code, Error.Message) of its ClientError. An unexpected SUCCESS
    raises, because reporting acceptance as a code mismatch would hide an over-permissive
    target behind a merely-wrong-value failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_usage_plan_key_if_present(apigw, plan_id, key_id):
    from botocore.exceptions import ClientError

    try:
        apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
