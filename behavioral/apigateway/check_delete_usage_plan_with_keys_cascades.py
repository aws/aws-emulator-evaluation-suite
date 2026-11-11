"""delete-usage-plan-with-keys-cascades."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-usage-plan-with-keys-cascades"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUsagePlan succeeds while an API key is still associated with the plan: the association goes
    with the plan and the API key itself is left untouched."""
    apigw = ctx.client("apigateway")
    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-planwithkeys-"),
        tags={"sim2real": "true"},
    )["id"]

    def _cleanup_plan() -> None:
        try:
            apigw.delete_usage_plan(usagePlanId=plan_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_plan)

    key_id = apigw.create_api_key(
        name=ctx.unique_name("sim2real-planwithkey-"),
        enabled=True,
        tags={"sim2real": "true"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")

    # Deletion is not rejected while the key association exists.
    apigw.delete_usage_plan(usagePlanId=plan_id)

    code_after, message_after = _client_error(lambda: apigw.get_usage_plan(usagePlanId=plan_id))
    assert code_after == "NotFoundException", f"expected plan to be gone, got {code_after!r}"
    assert message_after == "Invalid Usage Plan ID specified", message_after

    # The plan-key association is gone too (not left dangling).
    key_assoc_code, key_assoc_message = _client_error(lambda: apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    assert key_assoc_code == "NotFoundException", (
        f"expected the plan-key association to be gone too, got {key_assoc_code!r}"
    )
    assert key_assoc_message == "Invalid Usage Plan ID specified", key_assoc_message

    # The API key itself is unaffected by the usage-plan deletion.
    key = apigw.get_api_key(apiKey=key_id)
    assert key["id"] == key_id, f"expected the api key to survive the plan deletion, got {key!r}"

    # The plan id is genuinely dead, not merely unreadable: a mutation against
    # it (re-associating the key that was in the plan) must also fail.
    remutate_code, remutate_message = _client_error(
        lambda: apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    )
    assert remutate_code == "NotFoundException", (
        f"expected a mutation on the deleted plan id to fail, got {remutate_code!r}"
    )
    assert remutate_message == "Invalid Usage Plan ID specified", remutate_message


def _client_error(fn: Any) -> tuple[str, str | None]:
    """Call fn(); return the (code, message) of its botocore error. An unexpected success raises,
    so an accepted call is reported as accepted rather than as a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
