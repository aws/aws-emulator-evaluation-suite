"""deploy-cfn-cluster-executes-step."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-cluster-executes-step"
GROUP = "deploy"
SERVICES = ["emr"]

_SIM2REAL_TAG = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EMR cluster deployed via CloudFormation actually accepts and completes a job step."""
    cfn = ctx.client("cloudformation")
    emr = ctx.client("emr")

    _vpc_id, subnet_id = _private_network(ctx, "m5.xlarge")
    service_role, ec2_profile = _create_emr_roles(ctx)

    stack_name = ctx.unique_name("sim2real-emr-cfn-")
    parameters = [
        {"ParameterKey": "SubnetId", "ParameterValue": subnet_id},
        {"ParameterKey": "ServiceRole", "ParameterValue": service_role},
        {"ParameterKey": "JobFlowRole", "ParameterValue": ec2_profile},
        {"ParameterKey": "ClusterName", "ParameterValue": ctx.unique_name("sim2real-emr-cfn-cluster-")},
    ]
    _create_stack_retrying_iam_propagation(cfn, stack_name, _CFN_TEMPLATE, parameters)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    cluster_id = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "ClusterId")

    cluster_state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
    assert cluster_state in ("STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"), (
        f"cluster {cluster_id} reported unexpected post-CREATE_COMPLETE state {cluster_state!r}"
    )

    step_ids = emr.add_job_flow_steps(
        JobFlowId=cluster_id,
        Steps=[
            {
                "Name": "sim2real-echo-step",
                "ActionOnFailure": "CONTINUE",
                "HadoopJarStep": {
                    "Jar": "command-runner.jar",
                    "Args": ["bash", "-c", "echo sim2real-cfn-step-ran"],
                },
            }
        ],
    )["StepIds"]
    step_id = step_ids[0]

    step = _poll_until(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in ("COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert step["Status"]["State"] == "COMPLETED", (
        f"step {step_id} on cluster {cluster_id} did not complete: {step['Status']}"
    )
    assert step["Status"]["Timeline"].get("EndDateTime") is not None, (
        f"step {step_id} reports COMPLETED but carries no EndDateTime: {step['Status']}"
    )

    # Independent read at a different operation than the one that mutated (add_job_flow_steps)
    # and than the one that polled (describe_step): the completed step must also be visible
    # through the cluster's own step listing, not just through its own record.
    listed_steps = emr.list_steps(ClusterId=cluster_id)["Steps"]
    listed_states = {s["Id"]: s["Status"]["State"] for s in listed_steps}
    assert listed_states.get(step_id) == "COMPLETED", (
        f"step {step_id} not visible as COMPLETED via list_steps on cluster {cluster_id}: {listed_states}"
    )

    described_cluster = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    assert described_cluster["Id"] == cluster_id, (
        f"describe_cluster returned Id {described_cluster['Id']!r}, expected {cluster_id!r}"
    )


_CFN_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  SubnetId:
    Type: String
  ServiceRole:
    Type: String
  JobFlowRole:
    Type: String
  ClusterName:
    Type: String
Resources:
  EmrCluster:
    Type: AWS::EMR::Cluster
    Properties:
      Name: !Ref ClusterName
      ReleaseLabel: emr-6.15.0
      Applications:
        - Name: Hadoop
      Instances:
        MasterInstanceGroup:
          InstanceCount: 1
          InstanceType: m5.xlarge
        CoreInstanceGroup:
          InstanceCount: 1
          InstanceType: m5.xlarge
        Ec2SubnetId: !Ref SubnetId
        KeepJobFlowAliveWhenNoSteps: true
      JobFlowRole: !Ref JobFlowRole
      ServiceRole: !Ref ServiceRole
      VisibleToAllUsers: true
      Tags:
        - Key: sim2real
          Value: "true"
Outputs:
  ClusterId:
    Value: !Ref EmrCluster
"""


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


_STACK_CREATE_TERMINAL = ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED")
_IAM_PROPAGATION_MARKERS = ("is not authorized to assume", "invalid instanceprofile", "iam role")


def _wait_stack_status(cfn, stack_name, terminal_statuses, *, timeout_s, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {terminal_statuses} within {timeout_s}s (last={last})")


def _wait_stack_deleted(cfn, stack_name, *, timeout_s=180.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except Exception:
            return
        if status == "DELETE_COMPLETE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not finish deleting within {timeout_s}s")


def _stack_failure_reasons(cfn, stack_name):
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return " | ".join(
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
        for e in events
        if e.get("ResourceStatus", "").endswith("FAILED")
    )


def _create_stack_retrying_iam_propagation(cfn, stack_name, template, parameters, *, retry_budget_s=300.0, interval_s=20.0):
    """The IAM roles this stack references were just created; EMR/CloudFormation can take a
    few seconds to see them. Retry stack creation itself (the real signal) within a bounded
    budget instead of sleeping blind before the first attempt."""
    deadline = time.monotonic() + retry_budget_s
    attempt = 0
    while True:
        attempt += 1
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=parameters,
            OnFailure="DO_NOTHING",
            Tags=_SIM2REAL_TAG,
        )
        status = _wait_stack_status(cfn, stack_name, _STACK_CREATE_TERMINAL, timeout_s=900.0)
        if status == "CREATE_COMPLETE":
            return
        reasons = _stack_failure_reasons(cfn, stack_name)
        cfn.delete_stack(StackName=stack_name)
        _wait_stack_deleted(cfn, stack_name)
        is_propagation_lag = any(marker in reasons.lower() for marker in _IAM_PROPAGATION_MARKERS)
        if not is_propagation_lag or time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_name} did not reach CREATE_COMPLETE after {attempt} attempt(s) "
                f"(bounded retry budget {retry_budget_s}s for IAM role propagation): "
                f"status={status}, reasons={reasons!r}"
            )
        time.sleep(interval_s)


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

    iam.create_role(
        RoleName=service_role_name,
        AssumeRolePolicyDocument=_emr_trust_policy("elasticmapreduce.amazonaws.com"),
        Tags=_SIM2REAL_TAG,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=service_role_name))
    svc_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn=svc_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=service_role_name, PolicyArn=svc_policy))

    iam.create_role(
        RoleName=ec2_role_name,
        AssumeRolePolicyDocument=_emr_trust_policy("ec2.amazonaws.com"),
        Tags=_SIM2REAL_TAG,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role_name))
    ec2_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    iam.attach_role_policy(RoleName=ec2_role_name, PolicyArn=ec2_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role_name, PolicyArn=ec2_policy))

    iam.create_instance_profile(InstanceProfileName=ec2_role_name, Tags=_SIM2REAL_TAG)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name))

    return service_role_name, ec2_role_name


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
