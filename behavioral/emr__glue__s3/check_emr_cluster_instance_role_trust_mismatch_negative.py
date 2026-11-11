"""emr-cluster-instance-role-trust-mismatch-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-cluster-instance-role-trust-mismatch-negative"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A step on a cluster whose instance profile role does not trust ec2.amazonaws.com does not
    complete and writes no marker, while the same step on a sibling cluster with a correctly trusted
    role completes and writes it."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    service_role = _create_emr_service_role(ctx)
    mismatched_profile = _create_emr_instance_profile(ctx, trust_service="glue.amazonaws.com")
    correct_profile = _create_emr_instance_profile(ctx, trust_service="ec2.amazonaws.com")

    # These steps only succeed if the instance can actually obtain credentials for its
    # instance-profile role via the EC2 instance metadata service, which requires the role's
    # trust policy to permit ec2.amazonaws.com to assume it. A trivial "echo" step would pass
    # either way, so each step must exercise the credentials by writing to S3.
    bad_steps = [
        {
            "Name": "creds-check",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {
                "Jar": "command-runner.jar",
                "Args": ["bash", "-c", f"echo ok | aws s3 cp - s3://{bucket}/proof/bad-ok.txt"],
            },
        }
    ]
    good_steps = [
        {
            "Name": "creds-check",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {
                "Jar": "command-runner.jar",
                "Args": ["bash", "-c", f"echo ok | aws s3 cp - s3://{bucket}/proof/good-ok.txt"],
            },
        }
    ]

    cluster_bad = _run_job_flow(
        ctx,
        name=ctx.unique_name("sim2real-emr-badtrust-"),
        service_role=service_role,
        instance_profile=mismatched_profile,
        steps=bad_steps,
        keep_alive=False,
    )
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_bad))

    cluster_good = _run_job_flow(
        ctx,
        name=ctx.unique_name("sim2real-emr-goodtrust-"),
        service_role=service_role,
        instance_profile=correct_profile,
        steps=good_steps,
        keep_alive=False,
    )
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_good))

    _poll_cluster_state(ctx, cluster_bad, {"TERMINATED", "TERMINATED_WITH_ERRORS"}, timeout_s=1500.0)
    _poll_cluster_state(ctx, cluster_good, {"TERMINATED", "TERMINATED_WITH_ERRORS"}, timeout_s=1500.0)

    emr = ctx.client("emr")
    bad_step_id = emr.list_steps(ClusterId=cluster_bad)["Steps"][0]["Id"]
    good_step_id = emr.list_steps(ClusterId=cluster_good)["Steps"][0]["Id"]
    bad_state = emr.describe_step(ClusterId=cluster_bad, StepId=bad_step_id)["Step"]["Status"]["State"]
    good_state = emr.describe_step(ClusterId=cluster_good, StepId=good_step_id)["Step"]["Status"]["State"]

    # Positive control: the correctly-trusted role DOES get instance-metadata credentials and
    # completes the S3 write.
    assert good_state == "COMPLETED", f"positive control step (correctly-trusted role) did not complete: {good_state}"
    obj = s3.get_object(Bucket=bucket, Key="proof/good-ok.txt")
    body = obj["Body"].read().decode()
    expected_body = "ok\n"
    assert body == expected_body, f"expected positive control's proof marker body to be {expected_body!r}, got {body!r}"

    # Effect absent: the mistrusted role never obtains valid instance credentials, so its step
    # never manages to write its proof marker to S3.
    assert bad_state != "COMPLETED", f"step on a mistrusted instance profile role was expected to fail, got {bad_state}"
    code = _head_object_error_code(ctx, bucket, "proof/bad-ok.txt")
    assert code == "404", f"expected mistrusted-role step's proof marker to be absent, got head_object code {code!r}"


# ===== helpers =====


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-trust-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
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


def _create_emr_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-emr-svc-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return name


def _create_emr_instance_profile(ctx: Any, trust_service: str = "ec2.amazonaws.com") -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-ec2-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    profile_name = role_name
    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    # No unconditional wait: IAM role/instance-profile propagation to EC2/EMR is absorbed by
    # _run_job_flow's bounded retry on the transient "does not exist"/"is invalid" errors below.
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
            if time.monotonic() < deadline and ("does not exist" in msg or "invalid" in msg or "not authorized" in msg):
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


def _poll_cluster_state(
    ctx: Any, cluster_id: str, terminal_states: set[str], timeout_s: float = 1200.0, interval_s: float = 20.0
) -> dict:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    cluster = None
    state = None
    while time.monotonic() < deadline:
        resp = emr.describe_cluster(ClusterId=cluster_id)
        cluster = resp["Cluster"]
        state = cluster["Status"]["State"]
        if state in terminal_states:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not reach {terminal_states} within {timeout_s}s (last={state})")


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
