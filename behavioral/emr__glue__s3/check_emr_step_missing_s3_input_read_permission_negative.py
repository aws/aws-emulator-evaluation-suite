"""emr-step-missing-s3-input-read-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-step-missing-s3-input-read-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A step reading an S3 path its instance role is denied s3:GetObject on FAILS and writes no
    marker, while a second step on the same cluster reading an unrestricted path COMPLETES and writes
    its marker."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    content = "emr-input-permission-check\n"
    s3.put_object(Bucket=bucket, Key="input-denied/data.txt", Body=content.encode())
    s3.put_object(Bucket=bucket, Key="input-allowed/data.txt", Body=content.encode())

    service_role = _create_emr_service_role(ctx)
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "DenyInputGet", "Effect": "Deny", "Action": "s3:GetObject", "Resource": f"{bucket_arn}/input-denied/*"}
        ],
    }
    instance_profile = _create_emr_instance_profile(ctx, extra_policy_document=deny_policy)

    denied_script = (
        f"hadoop fs -cat s3://{bucket}/input-denied/data.txt > /tmp/x1 && "
        f"echo ok | aws s3 cp - s3://{bucket}/proof/denied-ok.txt"
    )
    allowed_script = (
        f"hadoop fs -cat s3://{bucket}/input-allowed/data.txt > /tmp/x2 && "
        f"echo ok | aws s3 cp - s3://{bucket}/proof/allowed-ok.txt"
    )
    steps = [
        {
            "Name": "read-denied-path",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", denied_script]},
        },
        {
            "Name": "read-allowed-path",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", allowed_script]},
        },
    ]
    cluster_id = _run_job_flow(
        ctx,
        name=ctx.unique_name("sim2real-emr-readperm-"),
        service_role=service_role,
        instance_profile=instance_profile,
        steps=steps,
        keep_alive=False,
    )
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_id))

    emr = ctx.client("emr")
    step_list = emr.list_steps(ClusterId=cluster_id)["Steps"]
    step_list = sorted(step_list, key=lambda s: s["Name"])
    denied_step_id = next(s["Id"] for s in step_list if s["Name"] == "read-denied-path")
    allowed_step_id = next(s["Id"] for s in step_list if s["Name"] == "read-allowed-path")

    denied_state = _poll_step_state(ctx, cluster_id, denied_step_id, timeout_s=1500.0)
    allowed_state = _poll_step_state(ctx, cluster_id, allowed_step_id, timeout_s=1500.0)

    assert denied_state == "FAILED", f"expected denied-path step to FAIL, got {denied_state}"
    assert allowed_state == "COMPLETED", f"expected allowed-path (positive control) step to COMPLETE, got {allowed_state}"

    # Effect absent: the denied step never got far enough to write its downstream proof marker.
    code = _head_object_error_code(ctx, bucket, "proof/denied-ok.txt")
    assert code == "404", f"expected denied step's proof marker to be absent, got head_object code {code!r}"

    # Positive control confirms the same pipeline DOES persist an effect when allowed.
    obj = s3.get_object(Bucket=bucket, Key="proof/allowed-ok.txt")
    body = obj["Body"].read().decode()
    assert body == "ok\n", f"expected allowed step's proof marker body to be 'ok\\n', got {body!r}"


# ===== helpers =====


def _head_object_error_code(ctx: Any, bucket: str, key: str):
    """HeadObject's error code for `key`; an object that exists raises AssertionError."""
    s3 = ctx.client("s3")
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"]
    raise AssertionError(f"s3://{bucket}/{key} exists where its absence was expected")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-readperm-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; this is
        # the global CreateBucket API quirk, not a region pin by this check.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _create_emr_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-emr-svc-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return name


def _create_emr_instance_profile(ctx: Any, extra_policy_document: dict | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-ec2-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    if extra_policy_document is not None:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="extra-restriction", PolicyDocument=json.dumps(extra_policy_document)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="extra-restriction"))
    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    # IAM role/instance-profile propagation to EMR/EC2 is bounded by _run_job_flow's own
    # retry-on-transient-IAM-error loop below, not by a fixed wait here.
    return profile_name


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
    }
    if steps:
        kwargs["Steps"] = steps
    if log_uri:
        kwargs["LogUri"] = log_uri
    if bootstrap_actions:
        kwargs["BootstrapActions"] = bootstrap_actions

    # Retry RunJobFlow on IAM propagation errors for up to 90 s.
    deadline = time.monotonic() + 90.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while True:
        try:
            resp = emr.run_job_flow(**kwargs)
            return resp["JobFlowId"]
        except Exception as exc:  # noqa: BLE001 - retry only on transient IAM propagation errors
            msg = str(exc).lower()
            transient = (
                "does not exist" in msg
                or "not authorized" in msg
                or ("invalid" in msg and ("instanceprofile" in msg or "servicerole" in msg))
            )
            if time.monotonic() < deadline and transient:
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


def _poll_step_state(ctx: Any, cluster_id: str, step_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> str:
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
    raise AssertionError(f"step {step_id} did not reach a terminal state within {timeout_s}s (last={state})")


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
