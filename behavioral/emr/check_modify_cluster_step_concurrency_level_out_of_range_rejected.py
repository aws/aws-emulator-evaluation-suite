"""modify-cluster-step-concurrency-level-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cluster-step-concurrency-level-out-of-range-rejected"
GROUP = "validation"
SERVICES = ["emr"]

_PREFIX = "sim2real-behav-emrscl-"
_SCENARIO = "emr-modify-cluster-step-concurrency-bounds"
_TAGS = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]
INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-7.1.0"
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
# ModifyCluster answers two different messages under one code: a level of 1..6400 that is above
# 256 names the range, while 0 or below and anything above 6400 get the bare sentence.
_BARE_MESSAGE = "Invalid step concurrency level."
_RANGE_MESSAGE = "Invalid step concurrency level. Allowed level is from 1 to 256"
_ACCEPTED = 4
_LIVE_STATES = {"STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyCluster on a live cluster rejects StepConcurrencyLevel 0, 257 and 6401 with InvalidRequestException
    and exact messages (a range the Smithy model does not declare), while an in-range level is applied, read
    back, and survives the later refusals."""
    emr = ctx.client("emr")
    iam = ctx.client("iam")

    svc_role, ec2_role = _make_roles(ctx, iam)
    subnet = _make_network(ctx)
    cluster = _run_cluster(ctx, emr, svc_role, ec2_role, subnet)

    live = _poll(lambda: emr.describe_cluster(ClusterId=cluster)["Cluster"],
                 lambda c: c["Status"]["State"] in _LIVE_STATES | {"TERMINATED",
                                                                   "TERMINATED_WITH_ERRORS"},
                 timeout_s=120, interval_s=5, description="cluster reports a state")
    assert live["Status"]["State"] in _LIVE_STATES, (
        f"the cluster must be live before it is modified, got {live['Status']!r}")
    assert live["StepConcurrencyLevel"] == 1, (
        f"the cluster was launched with StepConcurrencyLevel 1, DescribeCluster says "
        f"{live['StepConcurrencyLevel']!r}")

    # Below the range.
    err = _error(lambda: emr.modify_cluster(ClusterId=cluster, StepConcurrencyLevel=0))
    assert err["Code"] == "InvalidRequestException", f"level 0: got {err!r}"
    assert err["Message"] == _BARE_MESSAGE, f"level 0: message was {err['Message']!r}"
    _assert_level(emr, cluster, 1, "after the refused level 0")

    # POSITIVE CONTROL: an in-range change is applied and read back.
    applied = emr.modify_cluster(ClusterId=cluster, StepConcurrencyLevel=_ACCEPTED)
    assert applied["StepConcurrencyLevel"] == _ACCEPTED, (
        f"ModifyCluster must answer with the level it applied, got {applied!r}")
    _assert_level(emr, cluster, _ACCEPTED, "after the accepted change")

    # Above the range: refused, and the applied level survives the refusal.
    err = _error(lambda: emr.modify_cluster(ClusterId=cluster, StepConcurrencyLevel=257))
    assert err["Code"] == "InvalidRequestException", f"level 257: got {err!r}"
    assert err["Message"] == _RANGE_MESSAGE, f"level 257: message was {err['Message']!r}"
    _assert_level(emr, cluster, _ACCEPTED, "after the refused level 257")

    err = _error(lambda: emr.modify_cluster(ClusterId=cluster, StepConcurrencyLevel=6401))
    assert err["Code"] == "InvalidRequestException", f"level 6401: got {err!r}"
    assert err["Message"] == _BARE_MESSAGE, f"level 6401: message was {err['Message']!r}"
    _assert_level(emr, cluster, _ACCEPTED, "after the refused level 6401")


def _error(fn) -> dict:
    """The ClientError's Error dict (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected ModifyCluster to be refused, but it succeeded: {result!r}")


def _assert_level(emr, cluster: str, want: int, when: str) -> None:
    got = emr.describe_cluster(ClusterId=cluster)["Cluster"]["StepConcurrencyLevel"]
    assert got == want, f"DescribeCluster StepConcurrencyLevel {when} is {got!r}, expected {want}"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only `not_found` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")


def _trust(service: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]})


def _iam_delete(fn, attempts: int = 10, delay: float = 15.0) -> None:
    """An IAM delete retried while EMR still holds the profile; NoSuchEntity means gone."""
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                return
            if code != "DeleteConflict" or i == attempts - 1:
                raise
            time.sleep(delay)


def _make_roles(ctx, iam):
    """The EMR service role and the EC2 instance profile, each delete registered at its create."""
    svc_role = ctx.unique_name(_PREFIX + "svc-")
    ec2_role = ctx.unique_name(_PREFIX + "ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_trust(
        "elasticmapreduce.amazonaws.com"), Tags=_TAGS)
    ctx.on_cleanup(lambda: _iam_delete(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: _iam_delete(
        lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_trust("ec2.amazonaws.com"),
                    Tags=_TAGS)
    ctx.on_cleanup(lambda: _iam_delete(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: _iam_delete(
        lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _iam_delete(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: _iam_delete(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role)))
    _poll(lambda: iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"],
          lambda p: bool(p["Roles"]), timeout_s=60, interval_s=5,
          description=f"instance profile {ec2_role} lists its role")
    return svc_role, ec2_role


def _make_network(ctx) -> str:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _terminate_and_wait(ctx, emr, cluster: str) -> None:
    """Terminate the cluster and wait for TERMINATED, so its ENIs start draining."""
    emr.terminate_job_flows(JobFlowIds=[cluster])
    _poll(lambda: emr.describe_cluster(ClusterId=cluster)["Cluster"]["Status"]["State"],
          lambda s: s in ("TERMINATED", "TERMINATED_WITH_ERRORS"),
          timeout_s=max(0.0, min(900.0, _cleanup_deadline(ctx) - time.monotonic())), interval_s=15,
          description=f"cluster {cluster} reaches TERMINATED")


def _run_cluster(ctx, emr, svc_role: str, ec2_role: str, subnet: str) -> str:
    """Launch a one-node cluster at StepConcurrencyLevel 1, retrying only IAM propagation."""
    name = ctx.unique_name(_PREFIX)
    deadline = time.monotonic() + 120
    while True:
        try:
            cluster = emr.run_job_flow(
                Name=name, ReleaseLabel=RELEASE_LABEL, ServiceRole=svc_role,
                JobFlowRole=ec2_role, VisibleToAllUsers=True, StepConcurrencyLevel=1, Tags=_TAGS,
                Instances={
                    "InstanceGroups": [{"Name": "Master", "InstanceRole": "MASTER",
                                        "InstanceType": INSTANCE_TYPE, "InstanceCount": 1,
                                        "Market": "ON_DEMAND"}],
                    "Ec2SubnetId": subnet, "KeepJobFlowAliveWhenNoSteps": True,
                    "TerminationProtected": False,
                })["JobFlowId"]
            break
        except ClientError as exc:
            message = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] != "ValidationException" \
                    or "Invalid InstanceProfile" not in message \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(_teardown(lambda: _terminate_and_wait(ctx, emr, cluster)))
    return cluster


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
