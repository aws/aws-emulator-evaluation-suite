"""list-notebook-executions-newest-first."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-notebook-executions-newest-first"
GROUP = "ordering"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListNotebookExecutions does not order executions by StartTime (real AWS returns an order
    uncorrelated with creation), but the order it returns is stable across identical queries."""
    emr = ctx.client("emr")
    cluster_id = _create_cluster(ctx)
    _wait_for_cluster_state(ctx, cluster_id, {"RUNNING", "WAITING"}, timeout_s=1500, interval_s=20)

    bucket, key = _upload_notebook(ctx)
    service_role_arn = _create_notebook_service_role(ctx)

    created_order = []
    for i in range(3):
        execution_id = _start_execution_with_role_retry(
            emr, cluster_id, service_role_arn, f"sim2real-nb-{i}", bucket, key, f"output/{i}.ipynb"
        )
        created_order.append(execution_id)
        ctx.on_cleanup(lambda e=execution_id: _stop_execution(ctx, e))
        # Wait for this execution to leave START_PENDING (i.e. actually pick up a StartTime)
        # before submitting the next one, so the three executions get distinct StartTime values.
        _poll_until(
            lambda eid=execution_id: emr.describe_notebook_execution(NotebookExecutionId=eid)[
                "NotebookExecution"
            ]["Status"],
            lambda status: status != "START_PENDING",
            timeout_s=180.0,
            interval_s=10.0,
        )

    listed = emr.list_notebook_executions(ExecutionEngineId=cluster_id)["NotebookExecutions"]
    listed_ids = [n["NotebookExecutionId"] for n in listed]
    ours_in_listed_order = [eid for eid in listed_ids if eid in created_order]

    assert set(ours_in_listed_order) == set(created_order), (
        f"ListNotebookExecutions did not return every created execution: created={created_order}, "
        f"listed(ours)={ours_in_listed_order}"
    )

    relisted = emr.list_notebook_executions(ExecutionEngineId=cluster_id)["NotebookExecutions"]
    reordered = [n["NotebookExecutionId"] for n in relisted if n["NotebookExecutionId"] in created_order]
    assert reordered == ours_in_listed_order, (
        f"ListNotebookExecutions returned a different order across two immediate, identical "
        f"calls -- real AWS does not sort this list by StartTime, but it must be stable: "
        f"first={ours_in_listed_order}, second={reordered}"
    )


# ===== helpers =====


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchEntity"):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")


def _start_execution_with_role_retry(
    emr, cluster_id: str, service_role_arn: str, name: str, bucket: str, key: str, output_key: str,
    *, timeout_s: float = 90.0, interval_s: float = 5.0,
) -> str:
    """The notebook service role's trust policy is eventually consistent in IAM: EMR may reject
    the first StartNotebookExecution call for a few seconds after the role is created. Retry the
    identical call, bounded, instead of guessing a fixed propagation delay."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return emr.start_notebook_execution(
                ExecutionEngine={"Id": cluster_id, "Type": "EMR"},
                ServiceRole=service_role_arn,
                NotebookExecutionName=name,
                NotebookS3Location={"Bucket": bucket, "Key": key},
                OutputNotebookS3Location={"Bucket": bucket, "Key": output_key},
            )["NotebookExecutionId"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _stop_execution(ctx, execution_id: str) -> None:
    emr = ctx.client("emr")
    try:
        emr.stop_notebook_execution(NotebookExecutionId=execution_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "InvalidRequestException"
            and any(f in err.get("Message", "") for f in ("Unable to stop Execution because it is in", "does not exist"))
        ):
            raise


def _default_subnet_id(ctx) -> str:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _ensure_default_emr_roles(ctx) -> tuple[str, str]:
    """This run's own EMR roles (see _own_emr_roles)."""
    return _own_emr_roles(ctx)


def _run_job_flow_with_role_retry(emr, **kwargs) -> str:
    """A freshly created/attached IAM role or instance profile is eventually consistent; EMR may
    reject the first RunJobFlow for a few seconds. Retry the identical call, bounded, instead of
    guessing a fixed propagation delay."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return emr.run_job_flow(**kwargs)["JobFlowId"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _create_cluster(ctx) -> str:
    emr = ctx.client("emr")
    subnet_id = _default_subnet_id(ctx)
    service_role, ec2_role = _ensure_default_emr_roles(ctx)
    cluster_id = _run_job_flow_with_role_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-nb-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}],
        ServiceRole=service_role,
        JobFlowRole=ec2_role,
        VisibleToAllUsers=True,
        Instances={
            "InstanceGroups": [
                {"Name": "master", "InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"Name": "core", "InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_id))
    return cluster_id


def _terminate_cluster(ctx, cluster_id: str) -> None:
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


def _wait_for_cluster_state(ctx, cluster_id: str, states: set, timeout_s: float, interval_s: float):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        last = desc["Status"]["State"]
        if last in states:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not reach {states} within {timeout_s}s (last={last})")


def _upload_notebook(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-nb-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _safe(lambda: _empty_and_delete_bucket(ctx, bucket)))

    notebook = {
        "cells": [{"cell_type": "code", "source": ["1 + 1\n"], "metadata": {}, "outputs": [], "execution_count": None}],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    key = "notebooks/sim2real-check.ipynb"
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(notebook).encode("utf-8"))
    return bucket, key


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_notebook_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-nb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    # StartNotebookExecution validates S3 access on the service role synchronously (real AWS
    # returns InvalidRequestException: "Service role not authorized to s3:ListBucket" without it).
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    # on_cleanup runs LIFO: register delete_role first so detach_role_policy (registered after,
    # thus popped first) clears the attachment before the role deletion is attempted.
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    # IAM role trust is eventually consistent; _start_execution_with_role_retry bounds the wait
    # for it to propagate instead of guessing a fixed delay here.
    return role_arn



_EMR_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EMR_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
_OWN_EMR_ROLES: dict = {}


def _own_emr_roles(ctx) -> tuple[str, str]:
    """This run's own EMR service role and EC2 role (the EC2 role's instance profile has the same
    name), created once per run and deleted on teardown after every cluster using them ended.

    A fresh account has no EMR default roles, and creating the shared default names would leak
    account state between checks."""
    cached = _OWN_EMR_ROLES.get(id(ctx))
    if cached and cached[0] is ctx:  # holding ctx keeps its id from being reused by a later run
        return cached[1]
    iam = ctx.client("iam")
    service_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")
    _OWN_EMR_ROLES[id(ctx)] = (ctx, (service_role, ec2_role))
    ctx.on_cleanup(lambda: _OWN_EMR_ROLES.pop(id(ctx), None))  # runs after the roles are deleted
    ctx.on_cleanup(lambda: _delete_own_emr_roles(ctx, service_role, ec2_role))
    for role, principal, policy in (
        (service_role, "elasticmapreduce.amazonaws.com", _EMR_SERVICE_POLICY),
        (ec2_role, "ec2.amazonaws.com", _EMR_EC2_POLICY),
    ):
        iam.create_role(
            RoleName=role,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
            }),
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
        iam.attach_role_policy(RoleName=role, PolicyArn=policy)
    iam.create_instance_profile(InstanceProfileName=ec2_role)
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    deadline = time.monotonic() + 120.0
    while True:  # IAM is eventually consistent: wait until both roles and the profile read back
        try:
            iam.get_role(RoleName=service_role)
            iam.get_role(RoleName=ec2_role)
            profile = iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"]
            if any(r["RoleName"] == ec2_role for r in profile["Roles"]):
                break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        if time.monotonic() > deadline:
            raise AssertionError(f"EMR roles {service_role}/{ec2_role} did not become readable within 120s")
        time.sleep(3)
    return service_role, ec2_role


def _delete_own_emr_roles(ctx, service_role: str, ec2_role: str, timeout_s: float = 1200.0) -> None:
    """Delete this run's EMR roles once no live cluster uses the service role (EMR needs it to
    terminate its instances). If clusters still use it at the deadline the roles are kept, so
    the instances can still be terminated, and the leak is raised. Every delete step runs; the
    first failure is raised."""
    emr = ctx.client("emr")
    iam = ctx.client("iam")
    live = ["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING", "TERMINATING"]
    deadline = time.monotonic() + timeout_s
    while True:
        using = [
            c["Id"]
            for page in emr.get_paginator("list_clusters").paginate(ClusterStates=live)
            for c in page["Clusters"]
            if emr.describe_cluster(ClusterId=c["Id"])["Cluster"].get("ServiceRole") == service_role
        ]
        if not using:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"clusters {using} still use {service_role} after {timeout_s}s; roles kept")
        time.sleep(15)
    steps = (
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role),
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role),
        lambda: iam.detach_role_policy(RoleName=service_role, PolicyArn=_EMR_SERVICE_POLICY),
        lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EMR_EC2_POLICY),
        lambda: iam.delete_role(RoleName=service_role),
        lambda: iam.delete_role(RoleName=ec2_role),
    )
    errors = []
    for step in steps:
        try:
            step()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                errors.append(exc)
    if errors:
        raise errors[0]


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
