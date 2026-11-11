"""op-contract-cancel-spot-instance-requests."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-cancel-spot-instance-requests"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelSpotInstanceRequests transitions a real Spot Instance request to the
    'cancelled' state, and rejects a request ID that does not exist with
    InvalidSpotInstanceRequestID.NotFound."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    name = ctx.unique_name("sim2real-spotreq-")

    # Never rely on an ambient default VPC -- a freshly provisioned account may not have
    # one, and LaunchSpecification needs somewhere to land.
    vpc_id = ec2.create_vpc(CidrBlock="10.205.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": name}])
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.205.1.0/24", AvailabilityZone=az)[
        "Subnet"
    ]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": name}])

    # An intentionally low (but still validly-formatted) max price keeps the request 'open'
    # (unlikely to launch an instance), so the check has minimal instance-termination cost or
    # race to manage. AWS spot prices support at most 3 decimal places of precision -- a
    # 4-decimal-place price like "0.0001" is rejected as InvalidParameterValue, so the bid
    # must not go below that precision.
    resp = ec2.request_spot_instances(
        InstanceCount=1,
        Type="one-time",
        SpotPrice="0.001",
        LaunchSpecification={
            "ImageId": ami_id,
            "InstanceType": "t3.micro",
            "SubnetId": subnet_id,
        },
        TagSpecifications=[
            {"ResourceType": "spot-instances-request", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    request = resp["SpotInstanceRequests"][0]
    sir_id = request["SpotInstanceRequestId"]
    ctx.on_cleanup(lambda: _safe_cancel_and_reap(ec2, sir_id))

    _poll_until(
        lambda: ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[sir_id])[
            "SpotInstanceRequests"
        ][0]["State"],
        lambda state: state in ("open", "active"),
        timeout_s=30,
    )

    cancel_resp = ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=[sir_id])
    cancelled = cancel_resp["CancelledSpotInstanceRequests"]
    assert len(cancelled) == 1, f"expected exactly 1 cancelled request, got {cancelled!r}"
    assert cancelled[0]["SpotInstanceRequestId"] == sir_id, (
        f"expected cancelled id {sir_id}, got {cancelled[0]['SpotInstanceRequestId']!r}"
    )
    assert cancelled[0]["State"] == "cancelled", (
        f"expected State 'cancelled' in cancel response, got {cancelled[0]['State']!r}"
    )

    final_state = _poll_until(
        lambda: ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[sir_id])[
            "SpotInstanceRequests"
        ][0]["State"],
        lambda state: state == "cancelled",
        timeout_s=30,
    )
    assert final_state == "cancelled", (
        f"expected independent read to show 'cancelled', got {final_state!r}"
    )

    code, message = _error_detail(
        lambda: ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=["sir-00000000"])
    )
    assert code == "InvalidSpotInstanceRequestID.NotFound", (
        f"expected InvalidSpotInstanceRequestID.NotFound, got {code} ({message})"
    )
    assert message == "The spot instance request ID 'sir-00000000' does not exist", f"unexpected error message {message!r}"


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidSubnetID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _safe_cancel_and_reap(ec2, sir_id: str) -> None:
    try:
        ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=[sir_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSpotInstanceRequestID.NotFound":
            raise
    try:
        described = ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[sir_id])[
            "SpotInstanceRequests"
        ]
        instance_id = described[0].get("InstanceId") if described else None
        if instance_id:
            ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidInstanceID.NotFound",
            "InvalidSpotInstanceRequestID.NotFound",
        ):
            raise


def _error_detail(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
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
