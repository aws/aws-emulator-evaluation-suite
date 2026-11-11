"""e2e-notebook-execution-persistent-app-ui-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-notebook-execution-persistent-app-ui-flow"
GROUP = "e2e"
SERVICES = ["emr"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A notebook execution runs to completion; its persistent app UI's presigned URL is only
    obtainable once the UI has actually attached, not immediately after creation."""
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    cluster_id = _launch_notebook_cluster(ctx)
    _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s in ("WAITING", "RUNNING"),
        timeout_s=900.0,
        interval_s=20.0,
    )

    bucket = ctx.unique_name("sim2real-nb-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})

    notebook_key = "notebooks/sim2real.ipynb"
    s3.put_object(Bucket=bucket, Key=notebook_key, Body=json.dumps(_NOTEBOOK).encode("utf-8"))

    notebooks_role = _create_notebooks_role(ctx)

    def _run_notebook_execution_once():
        # RelativePath is documented for the EditorId (EMR-Notebook-editor) mode, not this ad-hoc
        # NotebookS3Location mode, so it is omitted.
        execution = _retry_on_client_error(lambda: emr.start_notebook_execution(
            NotebookExecutionName=ctx.unique_name("sim2real-nb-exec-"),
            ExecutionEngine={"Id": cluster_id, "Type": "EMR"},
            ServiceRole=notebooks_role,
            NotebookS3Location={"Bucket": bucket, "Key": notebook_key},
            # The output location and default (ipynb) output format of the passing
            # run-to-completion sibling.
            OutputNotebookS3Location={"Bucket": bucket, "Key": "notebooks/sim2real-output"},
        ))
        exec_id = execution["NotebookExecutionId"]
        result = _poll_until(
            lambda: emr.describe_notebook_execution(NotebookExecutionId=exec_id)["NotebookExecution"],
            lambda e: e["Status"] in ("FINISHED", "FAILED", "STOPPED"),
            timeout_s=900.0,
            interval_s=20.0,
        )
        return exec_id, result

    # StartNotebookExecution can return 200 and still FAIL the run: a freshly-WAITING cluster's
    # JupyterEnterpriseGateway/Livy service can still be settling for a short window after the
    # cluster itself reports WAITING, and a newly-attached role's permissions can still be
    # propagating to EMR's own check. Both surface as an execution-level FAILED, not a
    # StartNotebookExecution-level ClientError, so the whole execution is re-run up to 4 times
    # while another 900 s execution poll still fits the remaining time.
    for attempt in range(4):
        execution_id, described = _run_notebook_execution_once()
        if described["Status"] == "FINISHED" or attempt == 3:
            break
        left = ctx.time_left()
        if left is not None and left < 960:
            break
        time.sleep(2)
    assert described["Status"] == "FINISHED", (
        f"expected notebook execution {execution_id} to finish, got status={described['Status']!r} "
        f"(full response: {described!r})"
    )
    # A persistent application UI attaches to the EMR cluster the notebook ran on; real AWS
    # refuses a notebook execution ARN as its target ("Invalid input request").
    cluster_arn = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["ClusterArn"]

    ui = emr.create_persistent_app_ui(TargetResourceArn=cluster_arn)
    # The presigned URL is per UI type; the Spark History Server is the UI a notebook's Spark
    # job leaves behind.
    ui_id = ui["PersistentAppUIId"]

    # right after creation the UI has not attached yet -- the presigned URL must not be ready
    early = emr.get_persistent_app_ui_presigned_url(PersistentAppUIId=ui_id, PersistentAppUIType="SHS")
    assert early["PresignedURLReady"] is False, (
        f"expected PresignedURLReady=False immediately after create_persistent_app_ui, "
        f"got {early['PresignedURLReady']!r} (ui {ui_id})"
    )

    _poll_until(
        lambda: emr.describe_persistent_app_ui(PersistentAppUIId=ui_id)["PersistentAppUI"]["PersistentAppUIStatus"],
        # Real AWS reports a persistent app UI that attached to its cluster as ATTACHED.
        lambda s: s in ("ATTACHED", "FAILED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    final_status = emr.describe_persistent_app_ui(PersistentAppUIId=ui_id)["PersistentAppUI"]["PersistentAppUIStatus"]
    assert final_status == "ATTACHED", f"expected persistent app UI {ui_id} to reach ATTACHED, got {final_status!r}"

    attached = _poll_until(
        lambda: emr.get_persistent_app_ui_presigned_url(PersistentAppUIId=ui_id, PersistentAppUIType="SHS"),
        lambda r: r["PresignedURLReady"] is True,
        timeout_s=300.0,
        interval_s=15.0,
    )
    assert attached["PresignedURLReady"] is True, f"expected PresignedURLReady=True once ATTACHED, got {attached!r}"
    assert attached["PresignedURL"], f"expected a non-empty PresignedURL once ready, got {attached.get('PresignedURL')!r}"


_NOTEBOOK = {
    "cells": [
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": ["print('sim2real notebook ran')"],
        }
    ],
    "metadata": {
        "kernelspec": {"display_name": "PySpark", "language": "python", "name": "pysparkkernel"}
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _emr_trust_policy(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
        }
    )


def _create_emr_roles(ctx):
    iam = ctx.client("iam")
    service_role_name = ctx.unique_name("sim2real-emr-svc-")
    ec2_role_name = ctx.unique_name("sim2real-emr-ec2-")

    iam.create_role(RoleName=service_role_name, AssumeRolePolicyDocument=_emr_trust_policy("elasticmapreduce.amazonaws.com"), Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=service_role_name))
    svc_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn=svc_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=service_role_name, PolicyArn=svc_policy))

    iam.create_role(RoleName=ec2_role_name, AssumeRolePolicyDocument=_emr_trust_policy("ec2.amazonaws.com"), Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role_name))
    ec2_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    iam.attach_role_policy(RoleName=ec2_role_name, PolicyArn=ec2_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role_name, PolicyArn=ec2_policy))

    iam.create_instance_profile(InstanceProfileName=ec2_role_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name))

    return service_role_name, ec2_role_name


def _create_notebooks_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-nb-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_emr_trust_policy("elasticmapreduce.amazonaws.com"), Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
    # AmazonElasticMapReduceRole alone is not enough: a notebook execution creates an ENI to
    # reach the cluster's Livy/JupyterEnterpriseGateway endpoint, so the service role also needs
    # EC2 network-interface/security-group management -- without it EMR reports "Service Role
    # does not have the required permissions".
    inline_policy_name = "notebook-execution-network"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
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
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))
    return role_name


def _retry_on_client_error(fn, *, attempts=6, interval_s=10.0):
    """Bounded retry absorbing IAM eventual consistency: the role exists but EMR's own
    AssumeRole of it can lag a few seconds behind IAM's CreateRole/AttachRolePolicy response."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise last_err


def _run_job_flow_with_retry(emr, **kwargs):
    return _retry_on_client_error(lambda: emr.run_job_flow(**kwargs))


def _launch_notebook_cluster(ctx):
    emr = ctx.client("emr")
    # Roles before the network: cleanup runs LIFO, so the network teardown, which waits for the
    # cluster to terminate, finishes before the roles EMR needs to terminate it are deleted.
    service_role, ec2_profile = _create_emr_roles(ctx)
    _vpc_id, subnet_id = _private_network(ctx, "m5.xlarge")
    resp = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-nb-cluster-"),
        ReleaseLabel="emr-6.15.0",
        # JupyterEnterpriseGateway is required for EMR notebook executions to attach a kernel --
        # without it, StartNotebookExecution accepts the request but the execution fails with
        # "does not have JupyterEnterpriseGateway application installed".
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}, {"Name": "Livy"}, {"Name": "JupyterEnterpriseGateway"}],
        ServiceRole=service_role,
        JobFlowRole=ec2_profile,
        Instances={
            "InstanceGroups": [
                {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id


def _empty_and_delete_bucket(s3, bucket):
    objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


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


def _teardown_deadline(ctx, cap_s: float) -> float:
    """A teardown wait's deadline: cap_s from now, cut to the run's cleanup deadline given its ctx."""
    own = time.monotonic() + cap_s
    return own if ctx is None else min(own, _cleanup_deadline(ctx))


def _cleanup_spent(ctx) -> bool:
    """The run's cleanup deadline has passed; never without a ctx."""
    return ctx is not None and time.monotonic() >= _cleanup_deadline(ctx)


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
