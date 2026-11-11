"""notebook-execution-state-transitions-starting-to-finished."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notebook-execution-state-transitions-starting-to-finished"
GROUP = "state-machine"
SERVICES = ["emr"]

# Documented forward path for a notebook execution that completes without error.
_SUCCESS_ORDER = ["START_PENDING", "STARTING", "RUNNING", "FINISHING", "FINISHED"]
# A cluster reporting WAITING/RUNNING means the primary node is up, not that the
# Livy/JupyterEnterpriseGateway daemons the notebook-execution engine depends on have
# finished bootstrapping; real AWS observably fails an execution started too early with
# a terminal FAILED with no further detail. That is a cold-start race, not a backward
# transition, so it is retried with a fresh execution rather than asserted as the verdict.
_TERMINAL_FAILURE = {"FAILING", "FAILED"}
_MAX_EXECUTION_ATTEMPTS = 3


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A started notebook execution's status progresses monotonically to FINISHED, never backward."""
    emr = ctx.client("emr")
    bucket = _create_test_bucket(ctx)
    notebook_key = _upload_notebook(ctx, bucket, cell_source="print(1 + 1)\n")
    cluster_id, _cluster_service_role = _run_notebook_cluster(ctx)
    # A dedicated role, not the cluster's own EMR service role: real AWS's notebook-execution
    # engine needs ENI/security-group permissions to reach the cluster's Livy endpoint and
    # secretsmanager:GetSecretValue for the Livy session token, neither of which
    # AmazonElasticMapReduceRole grants. Created now so IAM propagation overlaps with the
    # cluster-boot wait below instead of needing its own wait.
    notebook_role = _ensure_notebook_execution_role(ctx)
    _wait_for_cluster_state(ctx, cluster_id, {"WAITING", "RUNNING"}, timeout_s=1500.0)

    last_status = None
    last_reason = None
    seen_indices: list[int] = []
    for _attempt in range(_MAX_EXECUTION_ATTEMPTS):
        last_status, last_reason, seen_indices = _run_one_notebook_execution(
            ctx, emr, cluster_id, notebook_role, bucket, notebook_key
        )
        if last_status not in _TERMINAL_FAILURE:
            break

    assert last_status == "FINISHED", (
        f"notebook execution never reached FINISHED after {_MAX_EXECUTION_ATTEMPTS} attempt(s), "
        f"last status={last_status}, reason={last_reason}"
    )
    assert seen_indices == sorted(seen_indices), f"observed status indices were not monotonic: {seen_indices}"


def _run_one_notebook_execution(
    ctx, emr, cluster_id: str, service_role: str, bucket: str, notebook_key: str
) -> tuple[str, dict | None, list[int]]:
    exec_name = ctx.unique_name("sim2real-nbexec-")
    resp = _start_notebook_execution_with_retry(
        emr,
        ExecutionEngine={"Id": cluster_id, "Type": "EMR"},
        ServiceRole=service_role,
        NotebookS3Location={"Bucket": bucket, "Key": notebook_key},
        OutputNotebookS3Location={"Bucket": bucket, "Key": f"output/{exec_name}"},
        NotebookExecutionName=exec_name,
    )
    execution_id = resp["NotebookExecutionId"]
    ctx.on_cleanup(lambda: _safe_stop_notebook_execution(ctx, execution_id))

    seen_indices: list[int] = []
    last_status = None
    last_reason = None
    deadline = time.monotonic() + 1500.0
    while time.monotonic() < deadline:
        execution = emr.describe_notebook_execution(NotebookExecutionId=execution_id)["NotebookExecution"]
        status = execution["Status"]
        if status != last_status:
            if status in _TERMINAL_FAILURE:
                last_status = status
                last_reason = execution.get("LastStateChangeReason")
                break
            assert status in _SUCCESS_ORDER, (
                f"notebook execution left the success path at status={status} "
                f"(history so far: {[_SUCCESS_ORDER[i] for i in seen_indices]})"
            )
            idx = _SUCCESS_ORDER.index(status)
            if seen_indices:
                assert idx >= seen_indices[-1], (
                    f"status regressed from {_SUCCESS_ORDER[seen_indices[-1]]} to {status}"
                )
            seen_indices.append(idx)
            last_status = status
            if status == "FINISHED":
                break
        time.sleep(2)
    else:
        raise AssertionError(f"notebook execution {execution_id} never reached a terminal state, last status={last_status}")

    return last_status, last_reason, seen_indices


# ===== helpers =====
def _safe_stop_notebook_execution(ctx, execution_id: str) -> None:
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


def _create_test_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-nb-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
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


def _upload_notebook(ctx, bucket: str, *, cell_source: str) -> str:
    s3 = ctx.client("s3")
    notebook = {
        "cells": [
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": [cell_source]}
        ],
        "metadata": {"kernelspec": {"display_name": "PySpark", "language": "python", "name": "pysparkkernel"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    key = f"input/{ctx.unique_name('sim2real-notebook-')}.ipynb"
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(notebook).encode("utf-8"))
    return key


def _default_subnet_id(ctx) -> str:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _delete_iam_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_remove_role_from_profile(ctx, profile_name: str, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _ensure_emr_cluster_roles(ctx, *, extra_service_policy_arns: list[str] | None = None) -> tuple[str, str]:
    iam = ctx.client("iam")
    service_role_name = ctx.unique_name("sim2real-emr-svc-")
    ec2_role_name = ctx.unique_name("sim2real-emr-ec2-")
    service_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    iam.create_role(RoleName=service_role_name, AssumeRolePolicyDocument=service_trust)
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, service_role_name))
    iam.attach_role_policy(
        RoleName=service_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    )
    for arn in extra_service_policy_arns or []:
        iam.attach_role_policy(RoleName=service_role_name, PolicyArn=arn)

    iam.create_role(RoleName=ec2_role_name, AssumeRolePolicyDocument=ec2_trust)
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, ec2_role_name))
    iam.attach_role_policy(
        RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    )
    iam.create_instance_profile(InstanceProfileName=ec2_role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name)
    ctx.on_cleanup(lambda: _safe_remove_role_from_profile(ctx, ec2_role_name, ec2_role_name))
    return service_role_name, ec2_role_name


def _run_job_flow_with_retry(emr, *, timeout_s: float = 120.0, interval_s: float = 10.0, **kwargs) -> dict:
    """EMR must be able to assume the roles just created; IAM's eventual consistency
    means the first run_job_flow attempt(s) can reject them until propagation catches up."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except ClientError as exc:
            msg = str(exc).lower()
            if "role" not in msg and "not authorized" not in msg and "instanceprofile" not in msg:
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"run_job_flow never accepted the newly created roles within {timeout_s}s: {last_err}")


def _start_notebook_execution_with_retry(emr, *, timeout_s: float = 120.0, interval_s: float = 10.0, **kwargs) -> dict:
    """Same IAM-eventual-consistency race as _run_job_flow_with_retry, for the notebook
    execution's own service role."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return emr.start_notebook_execution(**kwargs)
        except ClientError as exc:
            msg = str(exc).lower()
            if "role" not in msg and "not authorized" not in msg and "instanceprofile" not in msg:
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"start_notebook_execution never accepted the notebook role within {timeout_s}s: {last_err}")


def _ensure_notebook_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-nbexec-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="notebook-execution-network-and-s3",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateNetworkInterface",
                            "ec2:CreateNetworkInterfacePermission",
                            "ec2:DeleteNetworkInterface",
                            "ec2:DeleteNetworkInterfacePermission",
                            "ec2:DescribeNetworkInterfaces",
                            "ec2:ModifyNetworkInterfaceAttribute",
                            "ec2:AuthorizeSecurityGroupEgress",
                            "ec2:AuthorizeSecurityGroupIngress",
                            "ec2:CreateSecurityGroup",
                            "ec2:DescribeSecurityGroups",
                            "ec2:RevokeSecurityGroupEgress",
                            "ec2:DescribeTags",
                            "ec2:DescribeInstances",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeVpcs",
                            "ec2:CreateTags",
                            "elasticmapreduce:ListInstances",
                            "elasticmapreduce:DescribeCluster",
                            "elasticmapreduce:ListSteps",
                            "secretsmanager:GetSecretValue",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    return role_name


def _safe_terminate_cluster(ctx, cluster_id: str) -> None:
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


def _wait_for_cluster_state(
    ctx, cluster_id: str, target_states: set[str], *, timeout_s: float = 1500.0, interval_s: float = 30.0
) -> str:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        desc = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        last_state = desc["Status"]["State"]
        if last_state in target_states:
            return last_state
        if last_state in ("TERMINATED", "TERMINATED_WITH_ERRORS") and last_state not in target_states:
            reason = desc["Status"].get("StateChangeReason", {})
            raise AssertionError(f"cluster {cluster_id} reached {last_state} unexpectedly: {reason}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_states}, last state={last_state}")


def _run_notebook_cluster(ctx) -> tuple[str, str]:
    emr = ctx.client("emr")
    # Roles before the network: cleanup runs LIFO, so the network teardown, which waits for the
    # cluster to terminate, finishes before the roles EMR needs to terminate it are deleted.
    service_role, instance_profile = _ensure_emr_cluster_roles(
        ctx, extra_service_policy_arns=["arn:aws:iam::aws:policy/AmazonS3FullAccess"]
    )
    subnet_id = _default_subnet_id(ctx)
    instances: dict[str, Any] = {
        "InstanceGroups": [
            {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
        ],
        "Ec2SubnetId": subnet_id,
        "KeepJobFlowAliveWhenNoSteps": True,
        "TerminationProtected": False,
    }
    resp = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-nb-cluster-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}, {"Name": "Livy"}, {"Name": "JupyterEnterpriseGateway"}],
        Instances=instances,
        ServiceRole=service_role,
        JobFlowRole=instance_profile,
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _safe_terminate_cluster(ctx, cluster_id))
    return cluster_id, service_role


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
