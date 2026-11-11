"""deploy-emr-cluster-via-cloudformation-executes-step."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-emr-cluster-via-cloudformation-executes-step"
GROUP = "deploy"
SERVICES = ["emr"]


_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterName:
    Type: String
  SubnetId:
    Type: String
  ServiceRoleName:
    Type: String
  JobFlowRoleName:
    Type: String
Resources:
  EMRCluster:
    Type: AWS::EMR::Cluster
    Properties:
      Name: !Ref ClusterName
      ReleaseLabel: emr-6.15.0
      Applications:
        - Name: Hadoop
      Instances:
        Ec2SubnetId: !Ref SubnetId
        KeepJobFlowAliveWhenNoSteps: true
        MasterInstanceGroup:
          InstanceType: m5.xlarge
          InstanceCount: 1
      ServiceRole: !Ref ServiceRoleName
      JobFlowRole: !Ref JobFlowRoleName
      VisibleToAllUsers: true
      Tags:
        - Key: sim2real
          Value: "true"
Outputs:
  ClusterId:
    Value: !Ref EMRCluster
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed EMR cluster reaches WAITING and actually executes a submitted step."""
    roles = _ensure_emr_roles(ctx)
    _vpc_id, subnet_id = _private_network(ctx, "m5.xlarge")

    outputs = _deploy_stack(
        ctx,
        _TEMPLATE,
        {
            "ClusterName": ctx.unique_name("sim2real-emr-cluster-"),
            "SubnetId": subnet_id,
            "ServiceRoleName": roles["service_role"],
            "JobFlowRoleName": roles["job_flow_role"],
        },
        "sim2real-emr-cfn-",
    )
    cluster_id = outputs["ClusterId"]

    # The CFN resource only reports CREATE_COMPLETE once the cluster is usable, but confirm
    # explicitly via the EMR API rather than trusting CFN's status alone.
    cluster = _wait_cluster_state(ctx, cluster_id, {"RUNNING", "WAITING"}, timeout_s=120)
    assert cluster["Status"]["State"] in ("RUNNING", "WAITING"), (
        f"expected the CFN-deployed cluster {cluster_id} to reach RUNNING/WAITING, "
        f"got {cluster['Status']['State']}"
    )

    emr = ctx.client("emr")
    step_id = emr.add_job_flow_steps(
        JobFlowId=cluster_id,
        Steps=[
            {
                "Name": "sim2real-cfn-step",
                "ActionOnFailure": "CONTINUE",
                "HadoopJarStep": {
                    "Jar": "command-runner.jar",
                    "Args": ["bash", "-c", "echo sim2real-cfn-step-ran"],
                },
            }
        ],
    )["StepIds"][0]

    step = _wait_step_state(ctx, cluster_id, step_id, {"COMPLETED"}, timeout_s=600)
    assert step["Status"]["State"] == "COMPLETED", (
        f"expected step {step_id} on CFN-deployed cluster {cluster_id} to reach COMPLETED, "
        f"got {step['Status']['State']}"
    )
    end_time = step["Status"]["Timeline"].get("EndDateTime")
    assert end_time is not None, (
        f"step {step_id} reports COMPLETED but its Timeline carries no EndDateTime: "
        f"{step['Status']['Timeline']!r}"
    )


# ===== helpers =====


def _ensure_emr_roles(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")
    svc_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    tags = [{"Key": "sim2real", "Value": "true"}]
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=svc_trust, Tags=tags)
    iam.attach_role_policy(RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, svc_role, "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=ec2_trust, Tags=tags)
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, ec2_role, "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=tags)
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: _delete_instance_profile_safe(ctx, ec2_role, ec2_role))

    return {"service_role": svc_role, "job_flow_role": ec2_role}


def _delete_role_safe(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_instance_profile_safe(ctx, profile_name: str, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _deploy_stack(ctx, template_body: str, parameters: dict[str, str], stack_name_prefix: str) -> dict[str, str]:
    from botocore.exceptions import WaiterError

    cfn = ctx.client("cloudformation")
    attempts = 5
    last_error: Exception | None = None
    for attempt in range(attempts):
        stack_name = ctx.unique_name(stack_name_prefix)
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
            Capabilities=["CAPABILITY_IAM"],
        )
        ctx.on_cleanup(lambda sn=stack_name: _delete_stack_and_wait(ctx, sn))
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
            )
        except WaiterError as exc:
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            reasons = " | ".join(
                e.get("ResourceStatusReason", "")
                for e in events
                if e.get("ResourceStatus", "").endswith("FAILED")
            )
            lowered = reasons.lower()
            # EMR/EC2 need to see the new roles before CFN can hand them off; that IAM
            # propagation lag is the only expected transient failure here, so it — not a
            # blind sleep — is what bounds the retry.
            is_iam_propagation = (
                "is invalid" in lowered
                or "cannot be assumed" in lowered
                or "not authorized" in lowered
                or "invalid instanceprofile" in lowered
            )
            last_error = AssertionError(
                f"stack {stack_name} did not reach CREATE_COMPLETE (attempt {attempt + 1}/{attempts}): {reasons}"
            )
            if not is_iam_propagation or attempt == attempts - 1:
                raise last_error from exc
            time.sleep(15 * (attempt + 1))
            continue
        resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        return {o["OutputKey"]: o["OutputValue"] for o in resp.get("Outputs", [])}
    raise last_error  # pragma: no cover — loop always returns or raises above


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 400})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _wait_cluster_state(ctx, cluster_id: str, target_states: set, timeout_s: float = 900, interval_s: float = 15) -> dict[str, Any]:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        cluster = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        last_state = cluster["Status"]["State"]
        if last_state in target_states:
            return cluster
        if last_state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise AssertionError(f"cluster {cluster_id} reached {last_state} before {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not reach {target_states} within {timeout_s}s (last={last_state})")


def _wait_step_state(ctx, cluster_id: str, step_id: str, target_states: set, timeout_s: float = 600, interval_s: float = 15) -> dict[str, Any]:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_state = None
    terminal_failed = {"CANCELLED", "FAILED", "INTERRUPTED"}
    while time.monotonic() < deadline:
        step = emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]
        last_state = step["Status"]["State"]
        if last_state in target_states:
            return step
        if last_state in terminal_failed:
            raise AssertionError(f"step {step_id} reached {last_state}, expected {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"step {step_id} did not reach {target_states} within {timeout_s}s (last={last_state})")


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
