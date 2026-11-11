"""vpc-origin-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-origin-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

# A freshly-created VPC origin is "Deploying" and rejects UpdateVpcOrigin with IllegalUpdate
# until CloudFront finishes propagating it (several minutes on real AWS), so the scored path
# waits for the terminal "Deployed" status, bounded by ctx.time_left(), before the update.
# The delete + "gone" teardown runs in `ctx.on_cleanup` (unscored), generously bounded.
_INSTANCE_RUNNING_TIMEOUT_S = 120.0
_DEPLOYED_TIMEOUT_S = 1500.0
_DEPLOYED_INTERVAL_S = 2.0
# Cleanup-only (unscored — runs after the harness's per-check timeout window) — generous.
_CLEANUP_MUTATE_TIMEOUT_S = 900.0
_CLEANUP_MUTATE_INTERVAL_S = 10.0
_CLEANUP_GONE_TIMEOUT_S = 900.0
_CLEANUP_GONE_INTERVAL_S = 10.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VPC origins support create->get->list->Deployed->update against a real EC2 network
    endpoint; the delete + "gone" teardown happens in cleanup (unscored)."""
    cf = ctx.client("cloudfront")
    if not hasattr(cf, "create_vpc_origin"):
        raise AssertionError("installed botocore does not support CreateVpcOrigin")

    instance_arn, instance_id = _launch_probe_instance(ctx)

    name = ctx.unique_name("sim2real-vpco-")
    try:
        created = cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": name,
                "Arn": instance_arn,
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
            }
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("UnsupportedOperation", "AccessDenied", "EntityLimitExceeded"):
            raise AssertionError(f"VPC origins unavailable for this account/region: {code}") from exc
        raise

    origin_id = created["VpcOrigin"]["Id"]
    created_arn = created["VpcOrigin"]["VpcOriginEndpointConfig"]["Arn"]
    assert created_arn == instance_arn, f"expected create to echo Arn={instance_arn!r}, got {created_arn!r}"

    def _cleanup() -> None:
        try:
            cf.get_vpc_origin(Id=origin_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
                return
            raise
        _mutate_vpc_origin_with_retry(
            ctx,
            origin_id,
            lambda tag: cf.delete_vpc_origin(Id=origin_id, IfMatch=tag),
            deadline=time.monotonic() + _CLEANUP_MUTATE_TIMEOUT_S,
            interval_s=_CLEANUP_MUTATE_INTERVAL_S,
        )
        _wait_vpc_origin_gone(
            ctx, origin_id, deadline=time.monotonic() + _CLEANUP_GONE_TIMEOUT_S, interval_s=_CLEANUP_GONE_INTERVAL_S
        )

    ctx.on_cleanup(_cleanup)

    got = cf.get_vpc_origin(Id=origin_id)
    got_port = got["VpcOrigin"]["VpcOriginEndpointConfig"]["HTTPPort"]
    assert got_port == 80, f"expected an independent get to show HTTPPort=80, got {got_port}"

    listed = cf.list_vpc_origins()
    ids = [i["Id"] for i in listed.get("VpcOriginList", {}).get("Items", [])]
    assert origin_id in ids, f"expected {origin_id} in ListVpcOrigins, got {ids}"

    deadline = time.monotonic() + min(_DEPLOYED_TIMEOUT_S, (ctx.time_left() or _DEPLOYED_TIMEOUT_S) - 5)
    while True:
        current = cf.get_vpc_origin(Id=origin_id)
        status = current["VpcOrigin"]["Status"]
        if status == "Deployed":
            break
        assert status == "Deploying", f"VPC origin {origin_id} left Deploying for status {status!r}, expected Deployed"
        assert time.monotonic() < deadline, (
            f"VPC origin {origin_id} did not reach Deployed before the check's deadline; last status {status!r}"
        )
        time.sleep(_DEPLOYED_INTERVAL_S)

    new_cfg = {
        "Name": name,
        "Arn": instance_arn,
        "HTTPPort": 8080,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "http-only",
    }
    updated = cf.update_vpc_origin(Id=origin_id, IfMatch=current["ETag"], VpcOriginEndpointConfig=new_cfg)
    updated_port = updated["VpcOrigin"]["VpcOriginEndpointConfig"]["HTTPPort"]
    assert updated_port == 8080, f"expected update response to show HTTPPort=8080, got {updated_port}"
    reread = cf.get_vpc_origin(Id=origin_id)
    reread_port = reread["VpcOrigin"]["VpcOriginEndpointConfig"]["HTTPPort"]
    assert reread_port == 8080, f"expected an independent re-read to show HTTPPort=8080, got {reread_port}"

    # Delete + "gone"/list-effect verification happens in `_cleanup` above (unscored).


# ===== helpers =====
def _launch_probe_instance(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    ssm = ctx.client("ssm")

    # Not every Availability Zone offers t3.micro; place the instance in one that does.
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": ["t3.micro"]}],
    )["InstanceTypeOfferings"]}
    subnets = [
        s for s in ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if s["AvailabilityZone"] in offered
    ]
    if not subnets:
        raise AssertionError("no shared network VPC subnet in a t3.micro zone to host a VPC-origin probe instance")
    subnet = subnets[0]
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

    # Bounded independently of the rest of the check's mutation waits — an EC2 instance
    # (t3.micro, standard AMI) reaching "running" well within this window is realistic on its own.
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id],
        WaiterConfig={"Delay": 2, "MaxAttempts": int(_INSTANCE_RUNNING_TIMEOUT_S // 2)},
    )

    account_id = sts.get_caller_identity()["Account"]
    arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"
    return arn, instance_id


def _mutate_vpc_origin_with_retry(ctx, origin_id: str, mutate_fn, deadline: float, interval_s: float = 10.0):
    """Attempt a VPC-origin mutation (UpdateVpcOrigin/DeleteVpcOrigin) immediately with the
    origin's CURRENT ETag, retrying with a freshly-refetched ETag only on the "still Deploying"
    signal (real AWS's way of saying the mutation can't land yet). UpdateVpcOrigin surfaces this
    as IllegalUpdate, but DeleteVpcOrigin surfaces the identical "not Deployed yet" condition as a
    distinct IllegalDelete error code — both need the same retry-with-fresh-ETag treatment.
    Attempt-first is strictly cheaper than a blind pre-wait: it costs nothing once the origin is
    already Deployed, and only pays the propagation latency when the mutation is genuinely
    rejected. This helper is used from cleanup (unscored, runs after the harness's per-check
    timeout window), so its deadline can be generous."""
    cf = ctx.client("cloudfront")
    etag = cf.get_vpc_origin(Id=origin_id)["ETag"]
    while True:
        try:
            return mutate_fn(etag)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("IllegalUpdate", "IllegalDelete") or time.monotonic() >= deadline:
                raise
            time.sleep(min(interval_s, max(deadline - time.monotonic(), 0.0)))
            etag = cf.get_vpc_origin(Id=origin_id)["ETag"]


def _wait_vpc_origin_gone(ctx, origin_id: str, deadline: float, interval_s: float = 10.0) -> bool:
    cf = ctx.client("cloudfront")
    while True:
        try:
            cf.get_vpc_origin(Id=origin_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
                return True
            raise
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(interval_s, max(deadline - time.monotonic(), 0.0)))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


