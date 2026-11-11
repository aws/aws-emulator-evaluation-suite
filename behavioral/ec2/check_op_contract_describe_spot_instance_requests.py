"""op-contract-describe-spot-instance-requests."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describe-spot-instance-requests"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSpotInstanceRequests answers with a list and returns a created one-time request by ID with
    its own fields; an unknown SpotInstanceRequestId fails with
    InvalidSpotInstanceRequestID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    # Success path: SpotInstanceRequestIds is optional -- listing all requires no resource.
    resp = ec2.describe_spot_instance_requests()
    assert "SpotInstanceRequests" in resp
    assert isinstance(resp["SpotInstanceRequests"], list)

    # Positive control: a real spot request described by ID. A low but valid max price keeps it open;
    # spot prices allow at most 3 decimal places ("0.0001" fails with InvalidParameterValue).
    ami_id = _latest_al2023_ami(ctx)
    subnet_id = _create_subnet(ctx, ec2, "10.74.0.0/16", "sim2real-describe-spotreq-net-")
    name = ctx.unique_name("sim2real-describe-spotreq-")
    create_resp = ec2.request_spot_instances(
        InstanceCount=1,
        Type="one-time",
        SpotPrice="0.001",
        LaunchSpecification={"ImageId": ami_id, "InstanceType": "t3.micro", "SubnetId": subnet_id},
        TagSpecifications=[
            {"ResourceType": "spot-instances-request", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    sir_id = create_resp["SpotInstanceRequests"][0]["SpotInstanceRequestId"]
    ctx.on_cleanup(lambda: _safe_cancel_and_reap(ec2, sir_id))

    # DescribeSpotInstanceRequests can lag RequestSpotInstances briefly ("id does not
    # exist" for a few seconds after the request was accepted), so tolerate that
    # transient not-found while polling for the request to become describable.
    described = _poll_until(
        lambda: ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[sir_id])[
            "SpotInstanceRequests"
        ][0],
        lambda req: req["State"] in ("open", "active"),
        timeout_s=30,
        ignore_not_found_code="InvalidSpotInstanceRequestID.NotFound",
    )
    assert described["SpotInstanceRequestId"] == sir_id
    assert described["Type"] == "one-time"
    assert described["LaunchSpecification"]["InstanceType"] == "t3.micro"

    # Error boundary: syntactically valid but nonexistent ID.
    fake_id = "sir-00000000"
    code, code_message = _error_code(
        lambda: ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[fake_id])
    )
    assert code == "InvalidSpotInstanceRequestID.NotFound", f"expected NotFound, got {code!r}"
    expected_code_message = f"The spot instance request ID '{fake_id}' does not exist"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_cancel_and_reap(ec2, sir_id: str) -> None:
    from botocore.exceptions import ClientError

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
            ec2.get_waiter("instance_terminated").wait(
                InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100}
            )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidInstanceID.NotFound",
            "InvalidSpotInstanceRequestID.NotFound",
        ):
            raise


def _create_subnet(ctx, ec2, cidr, name_prefix):
    """A scratch VPC plus one subnet, both registered for cleanup; returns the subnet id."""
    name = ctx.unique_name(name_prefix)
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda state: state == "available",
        timeout_s=60,
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr.replace("/16", "/24"),
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["State"],
        lambda state: state == "available",
        timeout_s=60,
    )
    return subnet_id


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, ignore_not_found_code=None):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            if ignore_not_found_code and exc.response["Error"]["Code"] == ignore_not_found_code:
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
