"""scheduling-policy-lifecycle."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "scheduling-policy-lifecycle"
GROUP = 'scheduling-policy'
SERVICES = ['batch']

def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


def _create_scheduling_policy(ctx, bat, name=None):
    name = name or ctx.unique_name("sim2real-behav-sp-")
    resp = bat.create_scheduling_policy(
        name=name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags={"sim2real:managed": "true"},
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_scheduling_policy(arn=arn)))
    return name, arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedulingPolicy / UpdateSchedulingPolicy / DeleteSchedulingPolicy round-trip."""
    bat = ctx.client("batch")
    name, arn = _create_scheduling_policy(ctx, bat)

    resp = bat.describe_scheduling_policies(arns=[arn])
    policies = resp["schedulingPolicies"]
    assert len(policies) == 1
    assert policies[0]["name"] == name
    assert policies[0]["fairsharePolicy"]["computeReservation"] == 0

    bat.update_scheduling_policy(
        arn=arn,
        fairsharePolicy={"computeReservation": 50, "shareDecaySeconds": 60, "shareDistribution": []},
    )
    resp = bat.describe_scheduling_policies(arns=[arn])
    assert resp["schedulingPolicies"][0]["fairsharePolicy"]["computeReservation"] == 50

    bat.delete_scheduling_policy(arn=arn)

    # DescribeSchedulingPolicies never raises on an unknown ARN -- it silently omits it
    # from the response (confirmed against real AWS via a mixed real/fake arns request
    # elsewhere in this suite), so the independent read here is an emptiness check, not
    # an error-code check.
    resp2 = bat.describe_scheduling_policies(arns=[arn])
    assert resp2["schedulingPolicies"] == [], (
        f"expected deleted scheduling policy to be omitted from Describe, got {resp2['schedulingPolicies']!r}"
    )

    # Gone must also mean unusable: a mutation against the dead arn is rejected, not
    # silently accepted (UpdateSchedulingPolicy on an unknown ARN raises ClientException).
    try:
        bat.update_scheduling_policy(arn=arn, fairsharePolicy={"computeReservation": 1})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ClientException", f"expected ClientException updating a deleted policy, got {code}"
        assert message == f"{arn} does not exist.", (
            f"expected message {arn + ' does not exist.'!r}, got {message!r}"
        )
    else:
        raise AssertionError("expected update_scheduling_policy on a deleted arn to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
