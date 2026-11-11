"""op-contract-updateschedulingpolicy."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-updateschedulingpolicy"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchedulingPolicy mutates the fairsharePolicy in place (visible via
    DescribeSchedulingPolicies) and rejects a nonexistent policy ARN with ClientException
    without disturbing the real policy."""
    batch = ctx.client("batch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-schedpol-")
    created = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "computeReservation": 1,
            "shareDecaySeconds": 3600,
            "shareDistribution": [{"shareIdentifier": "teamA", "weightFactor": 1.0}],
        },
        tags={"team": "sim2real", "purpose": "behavioral-check"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))

    describe_before = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    fairshare_before = describe_before["fairsharePolicy"]
    assert fairshare_before["computeReservation"] == 1, fairshare_before
    assert fairshare_before["shareDecaySeconds"] == 3600, fairshare_before

    # Success path: update the policy's decay window, compute reservation, and add a share.
    update_resp = batch.update_scheduling_policy(
        arn=arn,
        fairsharePolicy={
            "computeReservation": 2,
            "shareDecaySeconds": 7200,
            "shareDistribution": [
                {"shareIdentifier": "teamA", "weightFactor": 2.0},
                {"shareIdentifier": "teamB", "weightFactor": 1.0},
            ],
        },
    )
    assert update_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, update_resp["ResponseMetadata"]

    describe_after = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    fairshare_after = describe_after["fairsharePolicy"]
    assert fairshare_after["computeReservation"] == 2, fairshare_after
    assert fairshare_after["shareDecaySeconds"] == 7200, fairshare_after
    weights = {d["shareIdentifier"]: d["weightFactor"] for d in fairshare_after["shareDistribution"]}
    assert weights == {"teamA": 2.0, "teamB": 1.0}, weights

    # Error boundary: updating a nonexistent scheduling-policy ARN.
    bogus_name = ctx.unique_name("nonexistent-schedpol-")
    bogus_arn = f"arn:aws:batch:{ctx.region}:{account_id}:scheduling-policy/{bogus_name}"
    code, message = _client_error(
        lambda: batch.update_scheduling_policy(
            arn=bogus_arn, fairsharePolicy={"computeReservation": 5, "shareDecaySeconds": 60}
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code}"
    expected_message = f"{bogus_arn} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The real policy must be unaffected by the failed call against the bogus ARN.
    describe_final = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    fairshare_final = describe_final["fairsharePolicy"]
    assert fairshare_final["computeReservation"] == 2, fairshare_final
    assert fairshare_final["shareDecaySeconds"] == 7200, fairshare_final


# ===== helpers =====
def _client_error(fn) -> Any:
    """Call fn() expecting an AWS refusal; return its (Error.Code, Error.Message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
