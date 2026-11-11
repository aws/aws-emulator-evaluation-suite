"""list-notebook-executions-ordering-and-status-filter."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-notebook-executions-ordering-and-status-filter"
GROUP = "ordering"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListNotebookExecutions honors a Status filter and returns a stable order: of one execution
    that finishes and one that fails on the same cluster, the filter partitions them, and two
    consecutive unfiltered listings match."""
    emr = ctx.client("emr")
    bucket = _create_test_bucket(ctx)
    cluster_id, service_role = _run_notebook_cluster(ctx)
    _wait_for_cluster_state(ctx, cluster_id, {"WAITING", "RUNNING"}, timeout_s=900.0)
    # Status=WAITING only means the primary node is up, not that the Livy/JupyterEnterpriseGateway
    # daemons the notebook-execution engine depends on have finished bootstrapping (on real AWS an
    # execution started immediately after WAITING can spuriously FAIL); the retry below bounds it.

    ok_key = _upload_notebook(ctx, bucket, cell_source="print(1 + 1)\n")
    bad_key = _upload_notebook(ctx, bucket, cell_source="raise RuntimeError('sim2real-intentional-failure')\n")

    ok_id, ok_final = _run_execution_until(ctx, emr, cluster_id, service_role, bucket, ok_key, "ok", "FINISHED")
    bad_id = _start_execution(ctx, cluster_id, service_role, bucket, bad_key, "bad")
    bad_final = _poll_until(
        lambda: emr.describe_notebook_execution(NotebookExecutionId=bad_id)["NotebookExecution"]["Status"],
        lambda s: s in ("FINISHED", "FAILED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    # ok_final is guaranteed "FINISHED" here -- _run_execution_until raises otherwise.
    assert bad_final == "FAILED", f"expected the raising notebook to fail, got {bad_final}"

    finished_listed = {
        e["NotebookExecutionId"]
        for e in emr.list_notebook_executions(Status="FINISHED", ExecutionEngineId=cluster_id)["NotebookExecutions"]
    }
    failed_listed = {
        e["NotebookExecutionId"]
        for e in emr.list_notebook_executions(Status="FAILED", ExecutionEngineId=cluster_id)["NotebookExecutions"]
    }
    assert ok_id in finished_listed and ok_id not in failed_listed, (
        f"expected {ok_id} in Status=FINISHED listing and absent from Status=FAILED, "
        f"got finished={finished_listed} failed={failed_listed}"
    )
    assert bad_id in failed_listed and bad_id not in finished_listed, (
        f"expected {bad_id} in Status=FAILED listing and absent from Status=FINISHED, "
        f"got finished={finished_listed} failed={failed_listed}"
    )

    first_pass = [
        e["NotebookExecutionId"]
        for e in emr.list_notebook_executions(ExecutionEngineId=cluster_id)["NotebookExecutions"]
    ]
    second_pass = [
        e["NotebookExecutionId"]
        for e in emr.list_notebook_executions(ExecutionEngineId=cluster_id)["NotebookExecutions"]
    ]
    assert first_pass == second_pass, (
        f"unfiltered ListNotebookExecutions order was not stable across calls: {first_pass} vs {second_pass}"
    )
    assert set(first_pass) >= {ok_id, bad_id}, (
        f"expected both {ok_id} and {bad_id} in the unfiltered listing {first_pass}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")


def _run_execution_until(
    ctx, emr, cluster_id, service_role, bucket, key, tag, want_status, *, attempts: int = 2
) -> tuple[str, str]:
    """Start a fresh execution up to `attempts` times until it reaches `want_status`.

    A cluster at Status=WAITING can still be finishing Livy/JupyterEnterpriseGateway bootstrap, so
    the first execution can FAIL for reasons that have nothing to do with the notebook's own code.
    Retrying with a brand-new execution (not re-polling the same one) recovers from exactly that.
    """
    last_status = None
    last_reason = None
    execution_id = None
    for attempt in range(attempts):
        execution_id = _start_execution(ctx, cluster_id, service_role, bucket, key, f"{tag}-{attempt}")
        last_execution = _poll_until(
            lambda eid=execution_id: emr.describe_notebook_execution(NotebookExecutionId=eid)["NotebookExecution"],
            lambda e: e["Status"] in ("FINISHED", "FAILED"),
            timeout_s=600.0,
            interval_s=15.0,
        )
        last_status = last_execution["Status"]
        last_reason = last_execution.get("LastStateChangeReason")
        if last_status == want_status:
            return execution_id, last_status
        time.sleep(2)
    raise AssertionError(
        f"{tag} notebook execution never reached {want_status} after {attempts} attempts, "
        f"last execution={execution_id} last status={last_status} reason={last_reason!r}"
    )


def _start_execution(ctx, cluster_id, service_role, bucket, key, tag) -> str:
    emr = ctx.client("emr")
    resp = emr.start_notebook_execution(
        ExecutionEngine={"Id": cluster_id, "Type": "EMR"},
        ServiceRole=service_role,
        NotebookS3Location={"Bucket": bucket, "Key": key},
        OutputNotebookS3Location={"Bucket": bucket, "Key": f"output/{tag}"},
        NotebookExecutionName=ctx.unique_name(f"sim2real-nbexec-{tag}-"),
    )
    execution_id = resp["NotebookExecutionId"]
    ctx.on_cleanup(lambda: _safe_stop_notebook_execution(ctx, execution_id))
    return execution_id


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
        # "python3"/"Python 3" fails fast and consistently against real AWS on this cluster;
        # the PySpark kernel is required.
        "metadata": {
            "kernelspec": {"display_name": "PySpark", "language": "python", "name": "pysparkkernel"},
            "language_info": {"name": "python"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    key = f"input/{ctx.unique_name('sim2real-notebook-')}.ipynb"
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(notebook).encode("utf-8"))
    return key


def _default_subnet_id(ctx) -> str:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _safe_delete_role_policy(ctx, role_name: str, policy_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_iam_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
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
    # StartNotebookExecution's ServiceRole needs more than AmazonElasticMapReduceRole grants: the
    # notebook-execution engine sets up its own ENI/security-group for the Livy session and polls
    # cluster/instance state directly. Without this, executions start but fail fast regardless of
    # kernel or cluster readiness.
    iam.put_role_policy(
        RoleName=service_role_name,
        PolicyName="notebook-execution-network-and-status",
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
    ctx.on_cleanup(lambda: _safe_delete_role_policy(ctx, service_role_name, "notebook-execution-network-and-status"))

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


def _run_job_flow_with_retry(emr, *, deadline_s: float = 240.0, interval_s: float = 20.0, **params) -> dict:
    """RunJobFlow while IAM has not yet propagated the just-created role/profile to EMR.

    IAM is eventually consistent; EMR rejects a role or instance profile it cannot see yet with
    "invalid InstanceProfile"/"invalid EC2 ...". That is the one condition worth retrying — anything
    else (a bad release label, a malformed request) must raise immediately.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return emr.run_job_flow(**params)
        except ClientError as exc:
            lowered = str(exc).lower()
            transient = "invalid instanceprofile" in lowered or "invalid ec2" in lowered
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
    ctx, cluster_id: str, target_states: set[str], *, timeout_s: float = 900.0, interval_s: float = 30.0
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
