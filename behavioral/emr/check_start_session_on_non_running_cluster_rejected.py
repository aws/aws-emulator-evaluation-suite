"""start-session-on-non-running-cluster-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-session-on-non-running-cluster-rejected"
GROUP = "negative-classes"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSession is rejected while the cluster is not yet RUNNING/WAITING, and
    succeeds once the very same cluster reaches WAITING (positive control)."""
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    emr = ctx.client("emr")
    cluster_id = _launch_session_enabled_cluster(ctx, run_state)

    # Immediately after RunJobFlow returns the cluster is still STARTING/BOOTSTRAPPING.
    state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
    assert state not in ("RUNNING", "WAITING"), f"cluster unexpectedly already {state}"

    code, message = _error_code(lambda: emr.start_session(ClusterId=cluster_id, Name="early-attempt"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = (
        f"StartSession is not supported for cluster '{cluster_id}' in state {state}. "
        f"The cluster must be in RUNNING or WAITING state."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    _wait_for_cluster_state(ctx, cluster_id, {"RUNNING", "WAITING"}, timeout_s=1800, interval_s=20)

    # Effect absent: the rejected attempt created no session on the cluster.
    sessions = emr.list_sessions(ClusterId=cluster_id).get("Sessions", [])
    assert sessions == [], "rejected StartSession call must not have created a session"

    # Positive control: the identical call succeeds once the cluster is WAITING.
    started = emr.start_session(ClusterId=cluster_id, Name="control-session")
    session_id = started["Id"]
    ctx.on_cleanup(lambda: emr.terminate_session(ClusterId=cluster_id, SessionId=session_id))
    assert started["State"] in ("SUBMITTED", "STARTING", "STARTED"), (
        f"unexpected initial state {started['State']!r}"
    )

    # Independent read at the destination: GetSession, never the mutating StartSession
    # response, is the terminal assertion.
    running = _poll_until(
        lambda: emr.get_session(ClusterId=cluster_id, SessionId=session_id)["Session"],
        lambda s: s["State"] in ("STARTED", "IDLE", "BUSY", "FAILED", "TERMINATED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert running["State"] in ("STARTED", "IDLE", "BUSY"), (
        f"session never reached a running state, last saw {running['State']!r}"
    )
    assert running["Id"] == session_id and running["ClusterId"] == cluster_id, (
        f"GetSession returned a mismatched session: {running!r}"
    )


# ===== helpers =====


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting a call real AWS refuses must fail as an acceptance,
    not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected StartSession to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _wait_for_cluster_state(ctx, cluster_id, target_states, timeout_s=900.0, interval_s=15.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in target_states:
            return state
        if state in ("TERMINATING", "TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise AssertionError(f"cluster {cluster_id} terminated unexpectedly ({state})")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_states}, last state {state}")


_SERVICE_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_EC2_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
)
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"


def _ensure_emr_roles(ctx) -> tuple[str, str]:
    """Create the EMR service and EC2-instance-profile roles this check needs, in-check —
    the account-wide EMR_DefaultRole/EMR_EC2_DefaultRole names are not guaranteed to exist
    (they require a prior `aws emr create-default-roles`, which a fresh sandbox never ran)."""
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_SERVICE_TRUST)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_role))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SESSIONS_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SESSIONS_POLICY))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_ENDPOINT_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_ENDPOINT_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))
    iam.create_instance_profile(InstanceProfileName=ec2_role)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role))

    _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"]["Roles"],
        lambda roles: len(roles) > 0,
        timeout_s=30.0,
        interval_s=2.0,
    )
    # No fixed propagation sleep: IAM -> EMR cross-service visibility races RunJobFlow, so
    # _run_job_flow_with_retry's bounded retry-on-role-error absorbs it instead.
    return svc_role, ec2_role


def _run_job_flow_with_retry(emr, timeout_s=120.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except ClientError as exc:
            msg = str(exc).lower()
            if ("not authorized" not in msg and "role" not in msg and "instanceprofile" not in msg
                    and "failed to authorize instance profile" not in msg):
                raise
            last_err = exc
            time.sleep(2)
    raise last_err


def _default_subnet(ctx, run_state: dict) -> str:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, run_state)[1]


def _launch_session_enabled_cluster(ctx, run_state: dict) -> str:
    emr = ctx.client("emr")
    svc_role, ec2_role = _ensure_emr_roles(ctx)
    subnet_id = _default_subnet(ctx, run_state)
    resp = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-sess-"),
        ReleaseLabel="emr-spark-8.0.0",
        Applications=[{"Name": "Spark"}],
        Instances={
            "InstanceGroups": [
                {"Name": "master", "InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"Name": "core", "InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        JobFlowRole=ec2_role,
        ServiceRole=svc_role,
        VisibleToAllUsers=True,
        SessionEnabled=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route; a gateway endpoint to
#: S3 and an interface endpoint to the EMR service (which EMR 8.x and EMR Spark 8.x clusters in a
#: private subnet call) are the only ways out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's 900 s cleanup budget less a margin: one deadline per run, started by the first
#: teardown that asks for it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 840.0
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound", "ResourceInUse",
})
#: Lets EMR create the Network Load Balancer and VPC endpoint service a Spark Connect session on a
#: private-subnet cluster needs.
_SESSIONS_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonEMRServicePolicyForSessions"
#: Lets EMR attach its security groups to the check's EMR service interface endpoint
#: (ec2:ModifyVpcEndpoint on resources tagged for-use-with-amazon-emr-managed-policies).
_ENDPOINT_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonEMRServicePolicy_v2"


def _private_network(ctx, run_state: dict, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type, its EMR service endpoint available; its teardown is registered before any
    cluster is placed in it."""
    if "network" in run_state:
        return run_state["network"]
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
    # AmazonEMRServicePolicyForSessions acts only on a VPC and subnet carrying the managed-policy tag.
    tags = [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "for-use-with-amazon-emr-managed-policies", "Value": "true"}]
    vpc_id = ec2.create_vpc(CidrBlock=_PRIVATE_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _drop_private_network(ctx, run_state, vpc_id))
    ctx.client("emr").meta.events.register(
        "after-call.emr.RunJobFlow", lambda parsed, **_: _track_cluster(ctx, run_state, parsed.get("JobFlowId")))
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
    _interface_endpoint(ctx, ec2, vpc_id, subnet_id, tags, f"aws.api.{ec2.meta.region_name}.emr-service-cell01")
    run_state["network"] = (vpc_id, subnet_id)
    return vpc_id, subnet_id


def _interface_endpoint(ctx, ec2, vpc_id: str, subnet_id: str, tags: list, service: str) -> None:
    """An interface endpoint to `service` in the subnet, with private DNS and HTTPS from the VPC,
    polled to available."""
    group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-endpoint-"), VpcId=vpc_id,
        Description=f"HTTPS from the VPC to {service}",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}])["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "IpRanges": [{"CidrIp": _PRIVATE_VPC_CIDR}]}])
    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc_id, VpcEndpointType="Interface", SubnetIds=[subnet_id], SecurityGroupIds=[group],
        ServiceName=service, PrivateDnsEnabled=True,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": tags}])["VpcEndpoint"]["VpcEndpointId"]
    deadline = time.monotonic() + min(300.0, ctx.time_left() or 300.0)
    while True:
        state = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint])["VpcEndpoints"][0]["State"]
        if state.lower() == "available":
            return
        assert state.lower() == "pending" and time.monotonic() < deadline, (
            f"endpoint {endpoint} to {service} is {state!r}, not available")
        time.sleep(2)


def _cleanup_deadline(ctx, run_state: dict) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    return run_state.setdefault("deadline", time.monotonic() + _CLEANUP_BUDGET_S)


def _track_cluster(ctx, run_state: dict, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        run_state.setdefault("clusters", set()).add(cluster_id)


def _drop_private_network(ctx, run_state: dict, vpc_id: str) -> None:
    """Delete the check's VPC: wait for its EMR clusters to terminate, delete the session load
    balancers and endpoint services EMR created, then its endpoints; wait for its interfaces to release,
    clear then delete every non-default group (EMR's reference each other), route tables, subnets, the
    VPC. Retries in-use refusals every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    run_state.pop("network", None)
    created = run_state.pop("clusters", set())
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
    elb = ctx.client("elbv2")
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = _cleanup_deadline(ctx, run_state)

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
        balancers = {b["LoadBalancerArn"] for page in elb.get_paginator("describe_load_balancers").paginate()
                     for b in page["LoadBalancers"] if b.get("VpcId") == vpc_id}
        services = [c for page in ec2.get_paginator("describe_vpc_endpoint_service_configurations").paginate()
                    for c in page["ServiceConfigurations"]
                    if balancers & set(c.get("NetworkLoadBalancerArns", []))
                    and c["ServiceState"].lower() != "deleted"]
        active = [c["ServiceId"] for c in services if c["ServiceState"].lower() != "deleting"]
        for service_id in active:
            # An endpoint service with an accepted or pending connection cannot be deleted.
            connected = [c["VpcEndpointId"] for c in ec2.describe_vpc_endpoint_connections(
                Filters=[{"Name": "service-id", "Values": [service_id]}])["VpcEndpointConnections"]
                if c["VpcEndpointState"].lower() in ("available", "pendingacceptance", "pending")]
            if connected:
                ec2.reject_vpc_endpoint_connections(ServiceId=service_id, VpcEndpointIds=connected)
        if active:
            failed = [u for u in ec2.delete_vpc_endpoint_service_configurations(ServiceIds=active).get(
                "Unsuccessful", []) if u["Error"]["Code"] != "InvalidVpcEndpointServiceId.NotFound"]
            if failed:
                raise RuntimeError(f"endpoint services in {vpc_id} not deleted: {failed!r}")
        if services:
            return f"endpoint services {[c['ServiceId'] for c in services]!r} are deleting"
        for arn in sorted(balancers):
            elb.delete_load_balancer(LoadBalancerArn=arn)
        if balancers:
            return f"load balancers {sorted(balancers)!r} are deleting"
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
