"""concurrent-container-instance-state-update."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-container-instance-state-update"
GROUP = 'concurrency'
SERVICES = ['ecs']


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnets(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnets available in this account/region")
    return [s["SubnetId"] for s in subnets]


def _default_sg(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in this account/region")
    return sgs[0]["GroupId"]


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _launch_real_container_instance(ctx, ecs, cluster, *, timeout_s=200):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]

    role_name = ctx.unique_name("ecsInstanceRole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]["Arn"]

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n"
    encoded_user_data = base64.b64encode(user_data.encode()).decode()

    last_exc = None
    instance_id = None
    left = ctx.time_left()
    launch_deadline = time.monotonic() + (40.0 if left is None else min(40.0, left))
    while instance_id is None and time.monotonic() < launch_deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Arn": profile_arn},
                SubnetId=subnets[0],
                SecurityGroupIds=[sg],
                UserData=encoded_user_data,
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": role_name}]}
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except Exception as exc:  # noqa: BLE001 — IAM propagation lag surfaces as a ClientError
            last_exc = exc
            time.sleep(2)
    if instance_id is None:
        raise last_exc or RuntimeError("failed to launch container-instance EC2 host")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    def _find():
        arns = ecs.list_container_instances(cluster=cluster).get("containerInstanceArns", [])
        if not arns:
            return None
        described = ecs.describe_container_instances(cluster=cluster, containerInstances=arns)[
            "containerInstances"
        ]
        for ci in described:
            if ci.get("ec2InstanceId") == instance_id:
                return ci
        return None

    ci = _poll_until(
        _find,
        lambda x: x is not None,
        timeout_s=timeout_s,
        interval_s=10,
        description="EC2 instance registers as an ECS container instance",
    )
    ctx.on_cleanup(
        lambda: ecs.deregister_container_instance(
            cluster=cluster, containerInstance=ci["containerInstanceArn"], force=True
        )
    )
    return ci


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateContainerInstancesState calls setting DRAINING and ACTIVE on the same
    container instance are both accepted, and DescribeContainerInstances settles to exactly one
    valid status, never a corrupted value."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    ci = _launch_real_container_instance(ctx, ecs, name)
    ci_arn = ci["containerInstanceArn"]

    def _drain():
        resp = ecs.update_container_instances_state(
            cluster=name, containerInstances=[ci_arn], status="DRAINING"
        )
        if resp.get("failures"):
            raise AssertionError(f"DRAINING update reported a per-instance failure: {resp['failures']}")
        return resp

    def _reactivate():
        resp = ecs.update_container_instances_state(
            cluster=name, containerInstances=[ci_arn], status="ACTIVE"
        )
        if resp.get("failures"):
            raise AssertionError(f"ACTIVE update reported a per-instance failure: {resp['failures']}")
        return resp

    results = _run_concurrent([_drain, _reactivate], timeout_s=30)
    successes = _concurrent_successes(results)
    assert successes == 2, (
        f"expected both concurrent UpdateContainerInstancesState calls to be individually accepted, "
        f"got {successes}/2 successes (codes: {_concurrent_error_codes(results)})"
    )

    def _status():
        return ecs.describe_container_instances(cluster=name, containerInstances=[ci_arn])[
            "containerInstances"
        ][0]["status"]

    settled = _poll_until(
        _status,
        lambda s: s in ("ACTIVE", "DRAINING"),
        timeout_s=30,
        interval_s=2,
        description="the container instance's status converges to one valid, singular value",
    )
    assert settled in ("ACTIVE", "DRAINING"), (
        f"expected the settled status to cleanly be ACTIVE or DRAINING, got {settled!r} "
        f"(anything else would indicate corrupted state)"
    )

    # Freeze check: repeated describes must report a single stable status.
    observed = [_status() for _ in range(3)]
    assert len(set(observed)) == 1, (
        f"expected repeated DescribeContainerInstances calls to report a single stable status, "
        f"got {observed}"
    )

    ecs.update_container_instances_state(cluster=name, containerInstances=[ci_arn], status="ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
