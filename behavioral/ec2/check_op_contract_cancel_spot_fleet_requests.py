"""op-contract-cancel-spot-fleet-requests."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-cancel-spot-fleet-requests"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelSpotFleetRequests reports an active zero-capacity Spot Fleet in SuccessfulFleetRequests and
    the fleet reaches cancelled; an unknown fleet request ID lands in UnsuccessfulFleetRequests with
    fleetRequestIdDoesNotExist and its exact message instead of raising."""
    ec2 = ctx.client("ec2")
    role_arn = _ensure_spot_fleet_role(ctx)
    ami_id = _latest_al2023_ami(ctx)

    fleet_name = ctx.unique_name("sim2real-spotfleet-")
    config = {
        "IamFleetRole": role_arn,
        "AllocationStrategy": "lowestPrice",
        "TargetCapacity": 0,
        "Type": "maintain",
        "LaunchSpecifications": [{"ImageId": ami_id, "InstanceType": "t3.micro"}],
        "TagSpecifications": [
            {"ResourceType": "spot-fleet-request", "Tags": [{"Key": "Name", "Value": fleet_name}]}
        ],
    }
    fleet_id = _request_spot_fleet_with_retry(ec2, config)
    ctx.on_cleanup(lambda: _safe_cancel_spot_fleet(ec2, fleet_id))

    state = _poll_until(
        lambda: ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[fleet_id])[
            "SpotFleetRequestConfigs"
        ][0]["SpotFleetRequestState"],
        lambda s: s != "submitted",
        timeout_s=60,
    )
    assert state == "active", f"expected the (zero-capacity) fleet to become active, got {state}"

    # TerminateInstances=False leaves instances running, so the fleet first reports cancelled_running,
    # or cancelled directly since a zero-capacity fleet has no instances.
    resp = ec2.cancel_spot_fleet_requests(
        SpotFleetRequestIds=[fleet_id], TerminateInstances=False
    )
    assert resp["UnsuccessfulFleetRequests"] == [], (
        f"expected no unsuccessful cancellations, got {resp['UnsuccessfulFleetRequests']}"
    )
    successes = resp["SuccessfulFleetRequests"]
    assert len(successes) == 1, f"expected exactly 1 successful cancellation, got {successes}"
    assert successes[0]["SpotFleetRequestId"] == fleet_id, (
        f"expected the cancelled id to be {fleet_id}, got {successes[0]['SpotFleetRequestId']}"
    )
    assert successes[0]["PreviousSpotFleetRequestState"] == "active", (
        "expected the previous state to be 'active', got "
        f"{successes[0]['PreviousSpotFleetRequestState']}"
    )
    assert successes[0]["CurrentSpotFleetRequestState"] in (
        "cancelled_running",
        "cancelled_terminating",
        "cancelled",
    ), (
        "expected the post-cancel state to be one of cancelled_running/cancelled_terminating/"
        f"cancelled, got {successes[0]['CurrentSpotFleetRequestState']}"
    )

    # With TerminateInstances=False the fleet stays in cancelled_running; a second cancellation that
    # requests termination moves it on to the terminal cancelled state.
    resp2 = ec2.cancel_spot_fleet_requests(SpotFleetRequestIds=[fleet_id], TerminateInstances=True)
    assert resp2["UnsuccessfulFleetRequests"] == [], (
        f"expected no unsuccessful cancellations, got {resp2['UnsuccessfulFleetRequests']}"
    )
    successes2 = resp2["SuccessfulFleetRequests"]
    assert len(successes2) == 1, f"expected exactly 1 successful cancellation, got {successes2}"
    assert successes2[0]["SpotFleetRequestId"] == fleet_id, (
        f"expected the cancelled id to be {fleet_id}, got {successes2[0]['SpotFleetRequestId']}"
    )

    # Spot Fleet can take over 180 s to move a zero-capacity fleet from cancelled_terminating to
    # cancelled, so poll longer for the terminal state.
    final_state = _poll_until(
        lambda: ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[fleet_id])[
            "SpotFleetRequestConfigs"
        ][0]["SpotFleetRequestState"],
        lambda s: s == "cancelled",
        timeout_s=600,
        interval_s=5.0,
    )
    assert final_state == "cancelled", f"expected the terminal state 'cancelled', got {final_state}"

    bogus_id = "sfr-00000000-0000-0000-0000-000000000000"
    error_resp = ec2.cancel_spot_fleet_requests(
        SpotFleetRequestIds=[bogus_id], TerminateInstances=True
    )
    assert error_resp["SuccessfulFleetRequests"] == [], (
        f"expected no successful cancellation of a nonexistent id, got {error_resp['SuccessfulFleetRequests']}"
    )
    failures = error_resp["UnsuccessfulFleetRequests"]
    assert len(failures) == 1, f"expected exactly 1 unsuccessful cancellation, got {failures}"
    assert failures[0]["SpotFleetRequestId"] == bogus_id, (
        f"expected the failed id to be {bogus_id}, got {failures[0]['SpotFleetRequestId']}"
    )
    assert failures[0]["Error"]["Code"] == "fleetRequestIdDoesNotExist", (
        f"expected error code fleetRequestIdDoesNotExist, got {failures[0]['Error']['Code']}"
    )
    assert failures[0]["Error"]["Message"] == "Spot Fleet Request cancellation failed. Spot Fleet Request not found.", (
        f"unexpected error message {failures[0]['Error']['Message']!r}"
    )


_SPOT_FLEET_TAGGING_POLICY_ARN = (
    "arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole"
)


def _ensure_spot_fleet_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-spotfleet-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "spotfleet.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SPOT_FLEET_TAGGING_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn=_SPOT_FLEET_TAGGING_POLICY_ARN
        )
    )
    return role_arn


def _request_spot_fleet_with_retry(ec2, config, *, timeout_s=60.0, interval_s=5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return ec2.request_spot_fleet(SpotFleetRequestConfig=config)["SpotFleetRequestId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "InvalidSpotFleetRequestConfig":
                raise
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(f"request_spot_fleet never succeeded (IAM propagation?): {last_error}")


def _safe_cancel_spot_fleet(ec2, fleet_id: str) -> None:
    ec2.cancel_spot_fleet_requests(SpotFleetRequestIds=[fleet_id], TerminateInstances=True)


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
