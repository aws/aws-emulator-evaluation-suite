"""emr-cluster-step-writes-output-to-s3-positive."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-cluster-step-writes-output-to-s3-positive"
GROUP = "resource-binding"
SERVICES = ["emr", "glue", "s3"]

MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-emr-write"},
]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An EMR step writes output through EMRFS to an S3 path, COMPLETES, and the object there holds
    exactly the expected content."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    token = ctx.unique_name("emr-output-data-")
    expected_content = f"{token}\n"

    service_role = _create_emr_service_role(ctx)
    instance_profile = _create_emr_instance_profile(ctx)

    script = f"echo '{token}' | aws s3 cp - s3://{bucket}/output/result.txt"
    steps = [
        {
            "Name": "write-to-s3",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {
                "Jar": "command-runner.jar",
                "Args": ["bash", "-c", script],
            },
        }
    ]
    cluster_id = _run_job_flow(
        ctx,
        name=ctx.unique_name("sim2real-emr-write-"),
        service_role=service_role,
        instance_profile=instance_profile,
        steps=steps,
        keep_alive=False,
    )
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_id))

    emr = ctx.client("emr")
    step_id = emr.list_steps(ClusterId=cluster_id)["Steps"][0]["Id"]

    state = _poll_step_state(ctx, cluster_id, step_id, timeout_s=1500.0)
    assert state == "COMPLETED", f"expected write step to COMPLETE, got {state}"

    obj = s3.get_object(Bucket=bucket, Key="output/result.txt")
    actual_content = obj["Body"].read().decode()
    assert actual_content == expected_content, (
        f"S3 output object content {actual_content!r} does not match what the cluster step wrote "
        f"({expected_content!r}); the step did not really persist its output to S3"
    )


# ===== helpers =====


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-write-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": MANAGED_TAGS})
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _create_emr_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-emr-svc-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=MANAGED_TAGS
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return name


def _create_emr_instance_profile(
    ctx: Any, extra_policy_document: dict | None = None
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-ec2-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    if extra_policy_document is not None:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="extra-restriction",
            PolicyDocument=json.dumps(extra_policy_document),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(
                RoleName=role_name, PolicyName="extra-restriction"
            )
        )
    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=MANAGED_TAGS)
    ctx.on_cleanup(
        lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)
    )
    iam.add_role_to_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    )
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )
    _wait_for_instance_profile_visible(ctx, profile_name)
    return profile_name


def _wait_for_instance_profile_visible(
    ctx: Any, profile_name: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> None:
    """Bounded poll for IAM's own eventually-consistent read of the profile+role it just created,
    so EMR/EC2 do not attempt to assume it before IAM itself reports it as attached."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            profile = iam.get_instance_profile(InstanceProfileName=profile_name)[
                "InstanceProfile"
            ]
            if profile.get("Roles"):
                return
        except Exception as exc:  # noqa: BLE001 - retry until IAM's own read reflects the write
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"instance profile {profile_name} did not become visible via IAM's own read within {timeout_s}s"
    ) from last_exc


def _default_subnet_id(ctx: Any) -> str:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _run_job_flow(
    ctx: Any,
    *,
    name: str,
    service_role: str,
    instance_profile: str,
    steps: list[dict] | None = None,
    log_uri: str | None = None,
    bootstrap_actions: list[dict] | None = None,
    keep_alive: bool = False,
) -> str:
    emr = ctx.client("emr")
    kwargs: dict[str, Any] = {
        "Name": name,
        "ReleaseLabel": "emr-6.15.0",
        "Applications": [{"Name": "Hadoop"}],
        "Instances": {
            "InstanceGroups": [
                {
                    "Name": "Primary",
                    "Market": "ON_DEMAND",
                    "InstanceRole": "MASTER",
                    "InstanceType": "m5.xlarge",
                    "InstanceCount": 1,
                }
            ],
            "Ec2SubnetId": _default_subnet_id(ctx),
            "KeepJobFlowAliveWhenNoSteps": keep_alive,
            "TerminationProtected": False,
        },
        "ServiceRole": service_role,
        "JobFlowRole": instance_profile,
        "VisibleToAllUsers": True,
        "Tags": MANAGED_TAGS,
    }
    if steps:
        kwargs["Steps"] = steps
    if log_uri:
        kwargs["LogUri"] = log_uri
    if bootstrap_actions:
        kwargs["BootstrapActions"] = bootstrap_actions

    # Retry RunJobFlow on IAM propagation errors for up to 60 s.
    deadline = time.monotonic() + 60.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while True:
        try:
            resp = emr.run_job_flow(**kwargs)
            return resp["JobFlowId"]
        except Exception as exc:  # noqa: BLE001 - retry only on transient IAM propagation errors
            msg = str(exc).lower()
            transient = (
                "does not exist",
                "is invalid",
                "not authorized",
                "invalid instanceprofile",
                "failed to authorize instance profile",
                "invalid servicerole",
            )
            if time.monotonic() < deadline and any(phrase in msg for phrase in transient):
                time.sleep(2)
                continue
            raise


def _terminate_cluster(ctx: Any, cluster_id: str) -> None:
    emr = ctx.client("emr")
    try:
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ValidationException"
            and "Specified job flow ID not valid" in err.get("Message", "")
        ):
            raise


def _poll_step_state(
    ctx: Any,
    cluster_id: str,
    step_id: str,
    timeout_s: float = 900.0,
    interval_s: float = 15.0,
) -> str:
    emr = ctx.client("emr")
    terminal = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        resp = emr.describe_step(ClusterId=cluster_id, StepId=step_id)
        state = resp["Step"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"step {step_id} did not reach a terminal state within {timeout_s}s (last={state})"
    )


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route, and a gateway
#: endpoint to S3 (all EMR needs there) is the only way out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's cleanup budget: one deadline per run, started by the first teardown that asks for
#: it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}
_CLUSTERS: dict[int, tuple[object, set[str]]] = {}
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
})
_NETWORKS: dict[int, tuple[object, tuple[str, str]]] = {}


def _private_network(ctx, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type; its teardown is registered before any cluster is placed in it."""
    hit = _NETWORKS.get(id(ctx))
    if hit is not None and hit[0] is ctx:
        return hit[1]
    ec2 = ctx.client("ec2")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]},
                 {"Name": "location", "Values": zones}])["InstanceTypeOfferings"]}
    usable = [z for z in zones if z in offered]
    assert usable, f"no available zone offers {instance_type}: zones {zones!r}"
    tags = [{"Key": "sim2real:managed", "Value": "true"}]
    vpc_id = ec2.create_vpc(CidrBlock=_PRIVATE_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _drop_private_network(ctx, vpc_id))
    ctx.client("emr").meta.events.register(
        "after-call.emr.RunJobFlow", lambda parsed, **_: _track_cluster(ctx, parsed.get("JobFlowId")))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_PRIVATE_SUBNET_CIDR, AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}])["Subnet"]["SubnetId"]
    table = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_vpc_endpoint(
        VpcId=vpc_id, VpcEndpointType="Gateway", RouteTableIds=[table],
        ServiceName=f"com.amazonaws.{ec2.meta.region_name}.s3",
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": tags}])
    _NETWORKS[id(ctx)] = (ctx, (vpc_id, subnet_id))
    return vpc_id, subnet_id


def _cleanup_deadline(ctx) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    hit = _cleanup_deadlines.get(id(ctx))
    if hit is None or hit[0] is not ctx:
        hit = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    return hit[1]


def _track_cluster(ctx, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        hit = _CLUSTERS.get(id(ctx))
        if hit is None or hit[0] is not ctx:
            hit = _CLUSTERS[id(ctx)] = (ctx, set())
        hit[1].add(cluster_id)


def _drop_private_network(ctx, vpc_id: str) -> None:
    """Delete the check's VPC: wait for its EMR clusters to terminate, delete its endpoints, wait for
    its interfaces to release, clear then delete every non-default group (EMR's reference each other),
    route tables, subnets, the VPC. Retries in-use refusals every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    _NETWORKS.pop(id(ctx), None)
    tracked = _CLUSTERS.pop(id(ctx), (ctx, set()))
    created = tracked[1] if tracked[0] is ctx else set()
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = _cleanup_deadline(ctx)

    def _emr_state(cluster_id: str) -> str:
        try:
            return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "").lower()
            if err["Code"] == "ClusterNotFound" or (
                    err["Code"] == "InvalidRequestException"
                    and ("not found" in message or "is not valid" in message)):
                return "TERMINATED"
            raise

    def _teardown_pass() -> str:
        """One pass: what the VPC still waits on, or "" once it is deleted."""
        clusters = sorted(created | {t["Value"] for r in ec2.describe_instances(Filters=in_vpc)["Reservations"]
                                     for i in r["Instances"] for t in i.get("Tags", [])
                                     if t["Key"] == "aws:elasticmapreduce:job-flow-id"})
        for cluster_id in clusters:
            state = _emr_state(cluster_id)
            if state not in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
                return f"cluster {cluster_id} is {state}"
        endpoints = [e for e in ec2.describe_vpc_endpoints(Filters=in_vpc)["VpcEndpoints"]
                     if e["State"].lower() != "deleted"]
        live = [e["VpcEndpointId"] for e in endpoints if e["State"].lower() != "deleting"]
        if live:
            failed = [u for u in ec2.delete_vpc_endpoints(VpcEndpointIds=live).get("Unsuccessful", [])
                      if u["Error"]["Code"] != "InvalidVpcEndpointId.NotFound"]
            if failed:
                raise RuntimeError(f"VPC endpoints of {vpc_id} not deleted: {failed!r}")
        if endpoints:
            return f"endpoints {[e['VpcEndpointId'] for e in endpoints]!r} are deleting"
        interfaces = ec2.describe_network_interfaces(Filters=in_vpc)["NetworkInterfaces"]
        attached = [n["NetworkInterfaceId"] for n in interfaces if n["Status"] != "available"]
        if attached:
            return f"interfaces {attached!r} are still attached"
        for n in interfaces:
            ec2.delete_network_interface(NetworkInterfaceId=n["NetworkInterfaceId"])
        groups = [g for g in ec2.describe_security_groups(Filters=in_vpc)["SecurityGroups"]
                  if g["GroupName"] != "default"]
        for g in groups:
            if g.get("IpPermissions"):
                ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
            if g.get("IpPermissionsEgress"):
                ec2.revoke_security_group_egress(
                    GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
        for g in groups:
            ec2.delete_security_group(GroupId=g["GroupId"])
        for table in ec2.describe_route_tables(Filters=in_vpc)["RouteTables"]:
            associations = table.get("Associations", [])
            if any(a.get("Main") for a in associations):
                continue
            for a in associations:
                ec2.disassociate_route_table(AssociationId=a["RouteTableAssociationId"])
            ec2.delete_route_table(RouteTableId=table["RouteTableId"])
        for s in ec2.describe_subnets(Filters=in_vpc)["Subnets"]:
            ec2.delete_subnet(SubnetId=s["SubnetId"])
        ec2.delete_vpc(VpcId=vpc_id)
        return ""

    while True:
        try:
            waiting = _teardown_pass()
            if not waiting:
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code not in _NETWORK_RETRY:
                raise RuntimeError(f"VPC {vpc_id} teardown: {exc}") from exc
            waiting = str(exc)
        if time.monotonic() >= deadline:
            raise RuntimeError(f"VPC {vpc_id} teardown missed the cleanup deadline: {waiting}")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
