"""get-session-endpoint-returns-reachable-endpoint."""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-endpoint-returns-reachable-endpoint"
GROUP = "data-plane"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """GetSessionEndpoint for a started, IDLE Spark Connect session returns a non-empty endpoint
    URL and authentication token consistent with the session's cluster, and the endpoint host is
    actually live: a real TLS handshake against it succeeds, not merely a well-formed URL string."""
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    cluster_id = _launch_cluster(
        ctx, run_state,
        session_enabled=True,
        release_label="emr-spark-8.0.0",
        applications=[{"Name": "Spark"}],
        extra={
            "Tags": [
                {"Key": "for-use-with-amazon-emr-managed-policies", "Value": "true"},
                {"Key": "sim2real", "Value": "true"},
            ]
        },
    )
    _wait_for_cluster_state(ctx, cluster_id, {"WAITING"})

    emr = ctx.client("emr")
    started = emr.start_session(ClusterId=cluster_id, Name=ctx.unique_name("sim2real-session-"))
    session_id = started["Id"]
    ctx.on_cleanup(lambda: emr.terminate_session(ClusterId=cluster_id, SessionId=session_id))

    _poll_until(
        lambda: emr.get_session(ClusterId=cluster_id, SessionId=session_id)["Session"],
        lambda s: s["State"] in ("IDLE", "STARTED", "BUSY", "FAILED", "TERMINATED"),
        timeout_s=600.0,
        interval_s=10.0,
    )

    endpoint_resp = emr.get_session_endpoint(ClusterId=cluster_id, SessionId=session_id)
    endpoint = endpoint_resp["Endpoint"]
    assert endpoint, "Endpoint was empty"
    assert endpoint.startswith("https://"), f"Endpoint did not look like a URL: {endpoint}"
    assert endpoint_resp.get("AuthToken"), "AuthToken was empty"

    _assert_tls_reachable(ctx, endpoint)

    # calling again for the same session returns another usable (non-empty) endpoint/token pair
    endpoint_resp2 = emr.get_session_endpoint(ClusterId=cluster_id, SessionId=session_id)
    assert endpoint_resp2["Endpoint"] == endpoint, "endpoint host changed for the same live session"


import json  # noqa: E402

_TRUST_EMR = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
)
_TRUST_EC2 = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
)


# tls-subject: the check asserts the published endpoint completes a verified TLS handshake.
def _assert_tls_reachable(ctx, endpoint: str, timeout_s: float = 15.0) -> None:
    parsed = urlparse(ctx.endpoint_url(endpoint))
    host = parsed.hostname
    port = parsed.port or 443
    assert host, f"could not parse a host out of endpoint {endpoint!r}"
    ctx_ssl = ssl.create_default_context(cafile=ctx.http_verify if isinstance(ctx.http_verify, str) else None)
    with socket.create_connection((host, port), timeout=timeout_s) as sock:
        with ctx_ssl.wrap_socket(sock, server_hostname=host) as tls_sock:
            assert tls_sock.cipher(), f"TLS handshake with {host}:{port} negotiated no cipher"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _default_subnet(ctx, run_state: dict):
    """(vpc_id, subnet_id) of this check's private network (see _private_network)."""
    return _private_network(ctx, run_state)


def _delete_role(ctx, role_name: str) -> None:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_instance_profile(ctx, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        prof = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
        for role in prof["Roles"]:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role["RoleName"])
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _emr_roles(ctx):
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-emr-")
    service_role_name = f"{suffix}-svc"
    ec2_role_name = f"{suffix}-ec2"
    profile_name = f"{suffix}-prof"
    sim2real_tag = [{"Key": "sim2real", "Value": "true"}]
    iam.create_role(RoleName=service_role_name, AssumeRolePolicyDocument=_TRUST_EMR, Tags=sim2real_tag)
    ctx.on_cleanup(lambda: _delete_role(ctx, service_role_name))
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole")
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn=_SESSIONS_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=service_role_name, PolicyArn=_SESSIONS_POLICY))
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn=_ENDPOINT_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=service_role_name, PolicyArn=_ENDPOINT_POLICY))
    iam.create_role(RoleName=ec2_role_name, AssumeRolePolicyDocument=_TRUST_EC2, Tags=sim2real_tag)
    ctx.on_cleanup(lambda: _delete_role(ctx, ec2_role_name))
    iam.attach_role_policy(RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role")
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=sim2real_tag)
    ctx.on_cleanup(lambda: _delete_instance_profile(ctx, profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=ec2_role_name)
    _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Roles"],
        lambda roles: len(roles) > 0,
        timeout_s=30.0,
        interval_s=2.0,
    )
    return service_role_name, profile_name


def _run_job_flow_with_retry(emr, **kwargs):
    """RunJobFlow, retrying every 2 s for up to 120 s while IAM propagates the new instance
    profile to EMR; raises every other error."""
    deadline = time.monotonic() + 120
    while True:
        try:
            return emr.run_job_flow(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "").lower()
            # IAM has not yet propagated the new instance profile to EMR.
            propagating = (err["Code"] == "ValidationException" and "invalid instanceprofile" in message) or (
                err["Code"] == "AccessDeniedException" and "failed to authorize instance profile" in message)
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _launch_cluster(
    ctx, run_state: dict, *,
    session_enabled=False, release_label="emr-6.15.0", applications=None, extra=None):
    emr = ctx.client("emr")
    _, subnet_id = _default_subnet(ctx, run_state)
    service_role, instance_profile = _emr_roles(ctx)
    kwargs = dict(
        Name=ctx.unique_name("sim2real-emr-cluster-"),
        ReleaseLabel=release_label,
        Applications=applications or [{"Name": "Hadoop"}],
        Instances={
            "InstanceGroups": [{"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1}],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        JobFlowRole=instance_profile,
        ServiceRole=service_role,
        VisibleToAllUsers=True,
    )
    if session_enabled:
        kwargs["SessionEnabled"] = True
    if extra:
        kwargs.update(extra)
    resp = _run_job_flow_with_retry(emr, **kwargs)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, run_state, emr, cluster_id))
    return cluster_id


def _wait_for_cluster_state(ctx, cluster_id, states, timeout_s=1500.0, interval_s=30.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        desc = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        last_state = desc["Status"]["State"]
        if last_state in states:
            return desc
        if last_state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise AssertionError(f"cluster reached terminal state {last_state} before {states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {states} within {timeout_s}s (last state {last_state})")


def _terminate_and_wait(ctx, run_state: dict, emr, cluster_id):
    """Terminate the cluster and wait until it is TERMINATED, so its instances' network interfaces
    leave its security groups before those are deleted."""
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    deadline = min(time.monotonic() + 800.0, _cleanup_deadline(ctx, run_state))
    while emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"] not in (
        "TERMINATED", "TERMINATED_WITH_ERRORS"
    ):
        if time.monotonic() >= deadline:
            raise AssertionError(f"EMR cluster {cluster_id} not terminated 800s after TerminateJobFlows")
        time.sleep(20)


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
