"""create-usage-plan-key-nonexistent-key-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-usage-plan-key-nonexistent-key-not-found"
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
    """CreateUsagePlanKey referencing a keyId that does not exist must fail with NotFoundException,
    while an otherwise-identical call referencing a real API key succeeds -- proving the rejection
    is specific to the missing key and not a blanket denial of CreateUsagePlanKey.
    """
    ag = ctx.client("apigateway")
    plan_id = ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-apigw-plan-"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_usage_plan(usagePlanId=plan_id))

    # Positive control: a real API key associates cleanly, proving the account/credentials/plan
    # are otherwise healthy and CreateUsagePlanKey is not being rejected wholesale.
    real_key_id = ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-apigw-plankey-"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=real_key_id))
    ag.create_usage_plan_key(usagePlanId=plan_id, keyId=real_key_id, keyType="API_KEY")
    got = ag.get_usage_plan_key(usagePlanId=plan_id, keyId=real_key_id)
    assert got["id"] == real_key_id, f"positive control did not associate: {got}"

    # Negative: an otherwise-identical call referencing a keyId that does not exist.
    code, message = _error(
        lambda: ag.create_usage_plan_key(
            usagePlanId=plan_id, keyId="sim2real-behav-nonexistent-key-id", keyType="API_KEY"
        )
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException associating a nonexistent API key, got {code}"
    )
    expected = "Invalid API Key identifier specified"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent, at the destination: the plan's key list contains only the real key --
    # no phantom association for the nonexistent keyId was created.
    remaining = [k["id"] for k in ag.get_usage_plan_keys(usagePlanId=plan_id)["items"]]
    assert remaining == [real_key_id], f"expected only the real key associated, got {remaining}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
