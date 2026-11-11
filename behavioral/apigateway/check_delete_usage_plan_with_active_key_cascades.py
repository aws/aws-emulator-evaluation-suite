"""delete-usage-plan-with-active-key-cascades."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-usage-plan-with-active-key-cascades"
GROUP = 'usage-plans'
SERVICES = ['apigateway']


def _client_error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.
    An unexpected SUCCESS raises, because a target accepting a call real AWS refuses must not
    read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUsagePlan succeeds (no ConflictException) while an API key is associated: the plan
    and its key association are gone, the key survives, and re-associating to the plan fails."""
    ag = ctx.client("apigateway")
    plan = ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-apigw-plandelcascade-"),
        tags={"sim2real": "true"},
    )
    plan_id = plan["id"]
    key = ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-apigw-plandelcascade-key-"),
        tags={"sim2real": "true"},
    )
    key_id = key["id"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=key_id))
    ag.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: _delete_usage_plan_if_present(ag, plan_id))

    ag.delete_usage_plan(usagePlanId=plan_id)

    code, message = _client_error(lambda: ag.get_usage_plan(usagePlanId=plan_id))
    assert code == "NotFoundException", (
        f"expected the plan to be gone (NotFoundException), got {code}"
    )
    assert message == "Invalid Usage Plan ID specified", message

    # The plan-key association is deleted with the plan.
    assoc_code, assoc_message = _client_error(
        lambda: ag.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    )
    assert assoc_code == "NotFoundException", (
        f"expected the plan-key association to be gone too, got {assoc_code}"
    )
    assert assoc_message == "Invalid Usage Plan ID specified", assoc_message

    surviving = ag.get_api_key(apiKey=key_id)
    assert surviving["id"] == key_id, (
        f"expected the api key to survive usage plan deletion, got {surviving!r}"
    )

    # The plan id is dead, not merely unreadable: re-associating the key must also fail.
    remutate_code, remutate_message = _client_error(
        lambda: ag.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    )
    assert remutate_code == "NotFoundException", (
        f"expected a mutation on the deleted plan id to fail, got {remutate_code}"
    )
    assert remutate_message == "Invalid Usage Plan ID specified", remutate_message

def _delete_usage_plan_if_present(ag, plan_id):
    """Teardown for a plan the check itself deletes: only an already-absent plan is tolerated."""
    try:
        ag.delete_usage_plan(usagePlanId=plan_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
