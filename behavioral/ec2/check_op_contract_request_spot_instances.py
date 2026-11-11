"""op-contract-request-spot-instances."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-request-spot-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestSpotInstances creates a trackable one-time spot request with
    the submitted launch spec (success contract), and synchronously rejects
    a launch spec referencing an unknown AMI with InvalidAMIID.NotFound."""
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ec2)
    name = ctx.unique_name("sim2real-spotreq-")
    resp = ec2.request_spot_instances(
        InstanceCount=1, Type="one-time",
        LaunchSpecification={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "spot-instances-request", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    req = resp["SpotInstanceRequests"][0]
    req_id = req["SpotInstanceRequestId"]

    def _cleanup():
        ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=[req_id])
        final = ec2.describe_spot_instance_requests(
            SpotInstanceRequestIds=[req_id])["SpotInstanceRequests"][0]
        instance_id = final.get("InstanceId")
        if instance_id:
            ec2.terminate_instances(InstanceIds=[instance_id])
    ctx.on_cleanup(_cleanup)

    assert req["Type"] == "one-time", f"expected Type=one-time, got {req['Type']!r}"
    assert req["LaunchSpecification"]["InstanceType"] == "t3.micro", (
        f"expected InstanceType=t3.micro, got {req['LaunchSpecification']['InstanceType']!r}")
    assert req["State"] in ("open", "active"), f"expected open/active, got {req['State']!r}"

    # DescribeSpotInstanceRequests can lag CreateSpotInstanceRequests briefly
    # ("id does not exist" for a few seconds after the request was accepted),
    # so tolerate that transient not-found while polling for a terminal state.
    final_state = _poll_until(
        lambda: ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[req_id])
        ["SpotInstanceRequests"][0]["State"],
        lambda s: s in ("active", "failed", "closed", "cancelled"), timeout_s=90, interval_s=5,
        ignore_not_found_code="InvalidSpotInstanceRequestID.NotFound")
    assert final_state != "failed", "spot instance request unexpectedly failed"

    # Unlike some launch-spec problems that only surface once the request is
    # evaluated, real AWS validates a nonexistent AMI in the launch spec
    # synchronously and rejects the RequestSpotInstances call itself with
    # InvalidAMIID.NotFound -- it never creates a request object for this
    # case. This only holds for a *well-formed* but unassigned AMI id though
    # -- AMI ids are not eligible for the 17-hex-char "long ID" format (they
    # stay at the original 8-hex-char length), so a 17-char id like
    # "ami-1234567890abcdef0" is rejected as InvalidAMIID.Malformed instead.
    # Use a well-formed (8-hex-char) but unassigned id instead.
    code, message = _error(lambda: ec2.request_spot_instances(
        InstanceCount=1, Type="one-time",
        LaunchSpecification={"ImageId": "ami-12345678", "InstanceType": "t3.micro"},
    ))
    assert code == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {code}"
    assert message == "The image id '[ami-12345678]' does not exist", (
        f"unexpected InvalidAMIID.NotFound message {message!r}")

    # Independent-read proof that the rejected call left no request object behind: no
    # successful RequestSpotInstances can ever reference this bogus AMI, so any match
    # here -- regardless of what else is concurrently running in this shared account --
    # means the target lied about rejecting the call synchronously.
    leaked = ec2.describe_spot_instance_requests(
        Filters=[{"Name": "launch.image-id", "Values": ["ami-12345678"]}]
    )["SpotInstanceRequests"]
    assert leaked == [], f"expected no spot request for rejected AMI, found {leaked}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0, ignore_not_found_code=None):
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


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no al2023 AMI found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

