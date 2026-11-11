"""describe-scheduling-policies-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-scheduling-policies-contract"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSchedulingPolicies returns the created policy's real fairshare config and rejects an oversized request."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")

    resp = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "computeReservation": 25,
            "shareDecaySeconds": 300,
            "shareDistribution": [{"shareIdentifier": "teamA", "weightFactor": 1.5}],
        },
        tags={"env": "sim2real-behav"},
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(batch, arn))

    found = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"]
    assert len(found) == 1, f"expected exactly 1 scheduling policy for arn {arn}, got {len(found)}"
    policy = found[0]
    assert policy["name"] == name, f"expected name {name!r}, got {policy['name']!r}"
    assert policy["fairsharePolicy"]["computeReservation"] == 25, (
        f"expected computeReservation 25, got {policy['fairsharePolicy']['computeReservation']!r}"
    )
    assert policy["fairsharePolicy"]["shareDecaySeconds"] == 300, (
        f"expected shareDecaySeconds 300, got {policy['fairsharePolicy']['shareDecaySeconds']!r}"
    )
    assert policy["fairsharePolicy"]["shareDistribution"][0]["shareIdentifier"] == "teamA", (
        "expected shareIdentifier 'teamA', got "
        f"{policy['fairsharePolicy']['shareDistribution'][0]['shareIdentifier']!r}"
    )
    assert policy["fairsharePolicy"]["shareDistribution"][0]["weightFactor"] == 1.5, (
        f"expected weightFactor 1.5, got {policy['fairsharePolicy']['shareDistribution'][0]['weightFactor']!r}"
    )
    assert policy["tags"] == {"env": "sim2real-behav"}, f"expected tags {{'env': 'sim2real-behav'}}, got {policy['tags']!r}"

    # Negative: describing more than the 100-ARN limit in a single call is rejected.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arns = [
        f"arn:aws:batch:{ctx.region}:{account_id}:scheduling-policy/sim2real-bogus-{i}" for i in range(101)
    ]
    code, message, request_id = _error(lambda: batch.describe_scheduling_policies(arns=bogus_arns))
    assert code == "ClientException", f"expected ClientException for >100 ARNs, got {code}"
    # The message embeds the RequestId of the rejected call, taken from that call's own response.
    expected_message = (
        "Error executing request, Exception : Number of scheduling policies should be between 1 and 100., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The real policy is unaffected by the rejected oversized request.
    still_found = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"]
    assert len(still_found) == 1 and still_found[0]["name"] == name, (
        f"expected the real policy {name!r} to remain describable after the rejected oversized "
        f"request, got {still_found!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (code, message, request id). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(batch, arn: str) -> None:
    batch.delete_scheduling_policy(arn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
