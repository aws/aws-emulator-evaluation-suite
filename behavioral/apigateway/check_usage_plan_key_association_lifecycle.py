"""usage-plan-key-association-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "usage-plan-key-association-lifecycle"
GROUP = 'usage-plans'
SERVICES = ['apigateway']


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlanKey associates an API key; DeleteUsagePlanKey removes the association
    and a repeat delete against the now-dead association 404s rather than silently succeeding."""
    ag = ctx.client("apigateway")
    plan = ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-apigw-plankey-"), tags={"sim2real": CHECK}
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: ag.delete_usage_plan(usagePlanId=plan_id))
    key = ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-apigw-plankey-apikey-"), tags={"sim2real": CHECK}
    )
    key_id = key["id"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=key_id))

    ag.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")

    got = ag.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    assert got["id"] == key_id, f"expected id {key_id!r}, got {got['id']!r}"

    ag.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    err = _client_error(
        lambda: ag.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    )
    assert (err.get("Code"), err.get("Message")) == ("NotFoundException", "Invalid Usage Plan ID specified"), (
        f"expected NotFoundException reading the deleted association, got {err!r}"
    )

    # the association is not just unreadable but genuinely gone: a mutation on the
    # dead id (a repeat delete) must also 404, never silently succeed a second time
    err = _client_error(
        lambda: ag.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    )
    assert (err.get("Code"), err.get("Message")) == ("NotFoundException", "Invalid Usage Plan ID specified"), (
        f"expected NotFoundException on repeat delete, got {err!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
