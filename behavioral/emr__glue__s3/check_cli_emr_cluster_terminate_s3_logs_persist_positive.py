"""cli-emr-cluster-terminate-s3-logs-persist-positive."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-emr-cluster-terminate-s3-logs-persist-positive"
GROUP = "cli-workflow"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """After the CLI terminates an EMR cluster whose LogUri points at S3, its log objects are in the bucket
    and still there on a second read: S3-persisted logs outlive the terminated cluster."""
    require_tools("aws")

    s3 = ctx.client("s3")
    emr = ctx.client("emr")
    bucket = _create_bucket(ctx)
    service_role, instance_profile = _create_emr_roles(ctx)
    subnet = _pick_subnet(ctx)

    cluster_name = ctx.unique_name("sim2real-emr-logs-")
    create_resp = _create_cluster_with_retry(
        ctx,
        "--name",
        cluster_name,
        "--release-label",
        "emr-6.15.0",
        "--applications",
        "Name=Hadoop",
        "--instance-type",
        _INSTANCE_TYPE,
        "--instance-count",
        "1",
        "--service-role",
        service_role,
        "--ec2-attributes",
        f"InstanceProfile={instance_profile},SubnetId={subnet}",
        "--log-uri",
        f"s3://{bucket}/logs/",
        "--steps",
        json.dumps(
            [
                {
                    "Name": "sim2real-trivial-step",
                    "Type": "CUSTOM_JAR",
                    "ActionOnFailure": "CONTINUE",
                    "Jar": "command-runner.jar",
                    "Args": ["bash", "-c", "echo sim2real-log-step"],
                }
            ]
        ),
    )
    cluster_id = create_resp["ClusterId"]
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_id))

    # The step must finish and the keep-alive cluster settle in WAITING before it is terminated,
    # otherwise there is nothing meaningful in the log prefix to check for persistence.
    steps = _poll_until(
        lambda: emr.list_steps(ClusterId=cluster_id)["Steps"],
        lambda st: len(st) == 1 and st[0]["Status"]["State"] in ("COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"),
        timeout_s=1200,
        interval_s=20,
    )
    assert steps[0]["Status"]["State"] == "COMPLETED", steps[0]["Status"]
    state = _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda st: st not in ("STARTING", "BOOTSTRAPPING", "RUNNING"),
        timeout_s=300,
        interval_s=15,
    )
    assert state == "WAITING", f"a keep-alive cluster whose only step finished must be WAITING, got {state!r}"

    _run_aws(ctx, "emr", "terminate-clusters", "--cluster-ids", cluster_id)

    cluster = _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"],
        lambda c: c["Status"]["State"] in ("TERMINATED", "TERMINATED_WITH_ERRORS"),
        timeout_s=600,
        interval_s=20,
    )
    assert cluster["Status"]["State"] == "TERMINATED", cluster["Status"]

    def _log_object_count() -> int:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=f"logs/{cluster_id}/")
        return resp.get("KeyCount", 0)

    # EMR flushes logs to S3 periodically and on termination; there is no promptness SLA, so
    # poll with a generous bounded window rather than asserting immediately.
    first_count = _poll_until(_log_object_count, lambda n: n > 0, timeout_s=600, interval_s=20)
    assert first_count > 0

    # Confirm persistence: logs must stay present across reads every 2 s over 30 s, not vanish
    # as a transient write cleaned up alongside the terminated cluster.
    deadline = time.monotonic() + 30.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while time.monotonic() < deadline:
        time.sleep(2)
        persisted_count = _log_object_count()
        assert persisted_count > 0, "log objects disappeared from S3 after the cluster was terminated"
    persisted_count = _log_object_count()
    assert persisted_count > 0, "log objects disappeared from S3 after the cluster was terminated"


# ===== helpers =====
_INSTANCE_TYPE = "m5.xlarge"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        env_extra={"AWS_PAGER": ""},
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-logs-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


_EMR_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EMR_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
_ROLE_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"}]


def _delete_with_retry(fn, attempts=8, delay=15):
    """Run an IAM delete, retrying DeleteConflict while EMR still holds the instance profile."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown; re-raised on the last attempt
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _create_emr_roles(ctx) -> tuple[str, str]:
    """Create the EMR service role and the EC2 instance profile this check uses; returns
    (service_role, instance_profile). Cleanups run LIFO, so each teardown is registered right
    after its create: remove-from-profile, delete profile, detach policies, delete roles."""
    iam = ctx.client("iam")
    trust = lambda principal: json.dumps({  # noqa: E731
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    })
    svc_role = ctx.unique_name("sim2real-xsvc-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-xsvc-emr-ec2-")
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=trust("elasticmapreduce.amazonaws.com"),
                    Tags=_ROLE_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_EMR_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_EMR_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=trust("ec2.amazonaws.com"), Tags=_ROLE_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EMR_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EMR_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_ROLE_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role))
    return svc_role, ec2_role


def _create_cluster_with_retry(ctx, *args: str, timeout_s=60.0, retry_deadline_s=240.0, interval_s=15.0):
    """create-cluster fails fast with "Invalid InstanceProfile" until the just-created instance
    profile has propagated to EMR. Retry on that specific error until the deadline instead of
    guessing a fixed delay; any other failure is raised at once."""
    deadline = time.monotonic() + retry_deadline_s
    while True:
        proc = _run_shell(ctx, ["aws", "--output", "json", "emr", "create-cluster", *args],
                          env_extra={"AWS_PAGER": ""}, timeout_s=timeout_s, check=False)
        if proc.returncode == 0:
            return json.loads(proc.stdout)
        if "InstanceProfile" not in proc.stderr or time.monotonic() >= deadline:
            raise AssertionError(
                f"aws emr create-cluster failed (rc={proc.returncode}): {proc.stderr[-500:]}")
        time.sleep(interval_s)


def _terminate_cluster(ctx, cluster_id: str) -> None:
    """Terminate and WAIT for TERMINATED: the roles, the VPC and the bucket are torn down after
    this (cleanups run LIFO), and EMR needs all three for the whole wind-down."""
    emr = ctx.client("emr")
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda st: st in ("TERMINATED", "TERMINATED_WITH_ERRORS"),
        timeout_s=900,
        interval_s=15,
    )


def _retry_ec2_delete(fn, budget_s=300):
    """Run an EC2 teardown call, retrying while its target is still held by something winding down."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code not in ("DependencyViolation", "InvalidNetworkInterface.InUse") or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _delete_vpc(ec2, vpc_id):
    """Delete the VPC after its non-default security groups: EMR creates its managed primary/core
    groups in it, and they reference each other, so their rules are revoked before the deletes."""
    groups = [g for g in ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"] if g["GroupName"] != "default"]
    for g in groups:
        if g.get("IpPermissions"):
            ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
        if g.get("IpPermissionsEgress"):
            ec2.revoke_security_group_egress(GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
    for g in groups:
        _retry_ec2_delete(lambda gid=g["GroupId"]: ec2.delete_security_group(GroupId=gid))
    _retry_ec2_delete(lambda: ec2.delete_vpc(VpcId=vpc_id))


def _pick_subnet(ctx):
    """A public subnet in a VPC this check creates, in an available AZ that offers _INSTANCE_TYPE.

    Both halves of the AZ choice are load-bearing: describe_instance_type_offerings says nothing
    about zone state, and describe_availability_zones says nothing about instance types. The
    internet gateway and default route give the cluster its egress. Cleanups run LIFO, so the route
    table goes first and the VPC last.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted({z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]} & offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {_INSTANCE_TYPE}; offerings were {sorted(offered)!r}"
    )

    vpc = ec2.create_vpc(CidrBlock="10.92.0.0/16",
                         TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.92.1.0/24", AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})

    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_ec2_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))

    rt = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_route_table(RouteTableId=rt)))
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    return subnet


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
