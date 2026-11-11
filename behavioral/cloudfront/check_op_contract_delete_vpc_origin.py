"""op-contract-deleteVpcOrigin."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpcOrigin"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

# CreateVpcOrigin rejects a well-formed but nonexistent EC2 instance ARN (InvalidArgument /
# InvalidInstanceID.Malformed), so the origin is backed by a real instance.
_INSTANCE_RUNNING_TIMEOUT_S = 120.0
# A fresh VPC origin is still Deploying and DeleteVpcOrigin answers IllegalDelete until the
# create propagates, which can take well over 120 s.
_DELETE_RETRY_TIMEOUT_S = 600.0
_DELETE_RETRY_INTERVAL_S = 2.0
# GetVpcOrigin can still return the origin right after a successful delete; the wait raises on
# timeout so "never checked" is not mistaken for "confirmed gone".
_GONE_TIMEOUT_S = 450.0
_GONE_INTERVAL_S = 2.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVpcOrigin rejects a malformed IfMatch with InvalidIfMatchVersion, succeeds with the
    correct ETag, and then GetVpcOrigin and a second delete both fail with EntityNotFound.
    """
    cf = ctx.client("cloudfront")
    if not hasattr(cf, "create_vpc_origin"):
        raise AssertionError("unreachable: create_vpc_origin not present in installed botocore")

    instance_arn = _launch_probe_instance(ctx)

    name = ctx.unique_name("sim2real-vpco-")
    try:
        created = cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": name,
                "Arn": instance_arn,
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
            }
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("UnsupportedOperation", "AccessDenied", "EntityLimitExceeded"):
            raise AssertionError(f"VPC origins unavailable for this account/region: {code}") from exc
        raise

    vo_id = created["VpcOrigin"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete(cf, vo_id))

    # distinct error boundary: a malformed IfMatch value is rejected regardless of deploy state
    code, msg = _error(lambda: cf.delete_vpc_origin(Id=vo_id, IfMatch="E000000000FAKEBOGUS"))
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {code}"
    assert msg == "The If-Match version is missing or not valid for the resource.", f"unexpected InvalidIfMatchVersion message: {msg!r}"

    # success path: retry with a freshly-refetched ETag while still Deploying
    etag = cf.get_vpc_origin(Id=vo_id)["ETag"]
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            cf.delete_vpc_origin(Id=vo_id, IfMatch=etag)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "IllegalDelete" or time.monotonic() >= deadline:
                raise
            time.sleep(_DELETE_RETRY_INTERVAL_S)
            etag = cf.get_vpc_origin(Id=vo_id)["ETag"]

    code_after, msg_after = _wait_gone(cf, vo_id, timeout_s=_GONE_TIMEOUT_S, interval_s=_GONE_INTERVAL_S)
    assert code_after == "EntityNotFound", f"expected EntityNotFound after delete, got {code_after}"
    assert msg_after == "The specified vpc origin does not exist", f"unexpected EntityNotFound message after delete: {msg_after!r}"

    # deletes prove gone AND unusable: a second delete on the now-dead Id fails the same way
    code_redelete, msg_redelete = _error(lambda: cf.delete_vpc_origin(Id=vo_id, IfMatch=etag))
    assert code_redelete == "EntityNotFound", f"expected EntityNotFound on re-delete, got {code_redelete}"
    assert msg_redelete == "The specified vpc origin does not exist", f"unexpected EntityNotFound message on re-delete: {msg_redelete!r}"


def _launch_probe_instance(ctx) -> str:
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    ssm = ctx.client("ssm")

    # Not every AZ offers t3.micro, so the instance goes in a network subnet of an AZ that does.
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": ["t3.micro"]}, {"Name": "location", "Values": ctx.network().availability_zones}],
        )["InstanceTypeOfferings"]
    }
    subnets = [
        s
        for s in ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if s["AvailabilityZone"] in offered
    ]
    if not subnets:
        raise AssertionError("no shared network VPC subnet in a t3.micro AZ to host a VPC-origin probe instance")
    subnet = sorted(subnets, key=lambda s: s["AvailabilityZone"])[0]
    vpc_id = subnet["VpcId"]

    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available for a VPC-origin probe instance")

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-vpco-probe-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["SubnetId"],
        SecurityGroupIds=[sgs[0]["GroupId"]],
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id],
        WaiterConfig={"Delay": 2, "MaxAttempts": int(_INSTANCE_RUNNING_TIMEOUT_S // 2)},
    )

    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises.
    A call that succeeds raises AssertionError, so an accepted call is never read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_gone(cf, vo_id: str, timeout_s: float, interval_s: float) -> "tuple[str, str]":
    """Poll GetVpcOrigin until it raises EntityNotFound; return that error's (code, message)."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while True:
        try:
            cf.get_vpc_origin(Id=vo_id)
            last_code = None
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last_code = err.get("Code")
            if last_code == "EntityNotFound":
                return last_code, err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"VPC origin {vo_id} did not become EntityNotFound within {timeout_s}s of a "
                f"successful delete (last observed: {last_code!r})"
            )
        time.sleep(interval_s)


def _safe_delete(cf, vo_id: str) -> None:
    try:
        current = cf.get_vpc_origin(Id=vo_id)
        cf.delete_vpc_origin(Id=vo_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
