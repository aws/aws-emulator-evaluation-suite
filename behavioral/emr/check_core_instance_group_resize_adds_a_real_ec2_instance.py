"""core-instance-group-resize-adds-a-real-ec2-instance."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "core-instance-group-resize-adds-a-real-ec2-instance"
GROUP = "cluster-lifecycle"
SERVICES = ["emr"]

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"
_CORE_START = 1
_CORE_TARGET = 2

_SCENARIO = "emr-core-resize"
_TAGS = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_EC2_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
# The non-terminated instance states: an instance EMR is still standing up counts towards the
# group, and one it has torn down must not.
LIVE_INSTANCE_STATES = ["AWAITING_FULFILLMENT", "PROVISIONING", "BOOTSTRAPPING", "RUNNING"]
#: Seconds over which the freeze detector's reads must agree before the resize, so "the count grew"
#: is a change this check caused rather than drift it happened to catch.
FREEZE_WINDOW_S = 30


def _swallow(fn):
    """Run fn(), swallowing any exception. TEARDOWN ONLY — never on an assertion path."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ValidationException"
            and "Specified job flow ID not valid" in err.get("Message", "")
        ):
            raise


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_with_retry(fn, attempts=8, delay=15):
    """Run an IAM delete, retrying DeleteConflict while EMR still holds the instance profile."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown; re-raised on the last attempt
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile; returns (service, ec2) names."""
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emrrz-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emrrz-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM is eventually consistent; _run_cluster retries RunJobFlow through the
    # role/profile-propagation errors with a deadline, on every target.
    return svc_role, ec2_role


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id):
    """Terminate and WAIT: cleanups run LIFO with the IAM deletions registered first, so a bare
    terminate lets delete_role run while EMR still needs it — stranding the EC2 fleet."""
    _swallow(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False))
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            time.sleep(2)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} did not terminate within the teardown wait")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors."""
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(emr, cluster_id))
    return cluster_id


def _groups(emr, cluster_id):
    """{InstanceGroupType: group} for the cluster, paginated."""
    out = {}
    for page in emr.get_paginator("list_instance_groups").paginate(ClusterId=cluster_id):
        for g in page["InstanceGroups"]:
            out[g["InstanceGroupType"]] = g
    return out


def _live_ec2_ids(emr, cluster_id, group_id):
    """The Ec2InstanceIds EMR currently attributes to one instance group, paginated."""
    return sorted(
        i["Ec2InstanceId"]
        for page in emr.get_paginator("list_instances").paginate(
            ClusterId=cluster_id, InstanceGroupId=group_id, InstanceStates=LIVE_INSTANCE_STATES)
        for i in page["Instances"]
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CORE instance-group resize provisions a real machine: after ModifyInstanceGroups raises the
    group from one node to two, ListInstances reports a new Ec2InstanceId that EC2 confirms as a
    running m5.xlarge it launched, and the primary group is untouched."""
    emr = ctx.client("emr")
    ec2 = ctx.client("ec2")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _private_network(ctx, INSTANCE_TYPE)[1]

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emrrz-"),
        ReleaseLabel=RELEASE_LABEL,
        Applications=[{"Name": "Hadoop"}],
        Instances={
            "InstanceGroups": [
                {"Name": "sim2real-primary", "InstanceRole": "MASTER",
                 "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND"},
                {"Name": "sim2real-core", "InstanceRole": "CORE",
                 "InstanceType": INSTANCE_TYPE, "InstanceCount": _CORE_START,
                 "Market": "ON_DEMAND"},
            ],
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
            "Ec2SubnetId": subnet,
        },
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    state = _poll(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s in TERMINAL_CLUSTER_STATES | {"WAITING", "RUNNING"},
        timeout_s=1500,
        interval_s=20,
        description=f"cluster {cluster_id} provisions",
    )
    assert state == "WAITING", (
        f"the resize needs a healthy WAITING cluster; got {state!r} (reason "
        f"{emr.describe_cluster(ClusterId=cluster_id)['Cluster']['Status'].get('StateChangeReason')!r})"
    )

    groups = _groups(emr, cluster_id)
    assert set(groups) == {"MASTER", "CORE"}, (
        f"the cluster must expose exactly the primary and core groups requested, got "
        f"{sorted(groups)!r}"
    )
    core_id = groups["CORE"]["Id"]
    primary_id = groups["MASTER"]["Id"]
    primary_before = (
        groups["MASTER"]["RequestedInstanceCount"], groups["MASTER"]["RunningInstanceCount"]
    )

    # --- freeze detector: the pre-resize state must be settled, so the growth below is caused
    # by this check's ModifyInstanceGroups and not by provisioning still finishing.
    baseline = []
    settle_until = time.monotonic() + FREEZE_WINDOW_S
    while True:
        baseline.append(_live_ec2_ids(emr, cluster_id, core_id))
        if time.monotonic() >= settle_until:
            break
        time.sleep(2)
    assert all(b == baseline[0] for b in baseline), (
        f"the CORE group must be settled before the resize: {len(baseline)} reads over "
        f"{FREEZE_WINDOW_S} s disagreed, "
        f"{baseline!r}"
    )
    before_ids = baseline[0]
    assert len(before_ids) == _CORE_START, (
        f"the CORE group must start with exactly {_CORE_START} non-terminated instance(s), got "
        f"{before_ids!r}"
    )

    # --- the mutation.
    emr.modify_instance_groups(
        ClusterId=cluster_id,
        InstanceGroups=[{"InstanceGroupId": core_id, "InstanceCount": _CORE_TARGET}],
    )

    requested = _poll(
        lambda: _groups(emr, cluster_id)["CORE"]["RequestedInstanceCount"],
        lambda n: n == _CORE_TARGET,
        timeout_s=300,
        interval_s=10,
        description=f"the CORE group's RequestedInstanceCount reaches {_CORE_TARGET}",
    )
    assert requested == _CORE_TARGET, (
        f"ModifyInstanceGroups must move RequestedInstanceCount to {_CORE_TARGET}, got {requested!r}"
    )

    # --- capacity actually arrives. Terminal set excludes the start value, so a target that never
    # grows times out rather than passing.
    after_ids = _poll(
        lambda: _live_ec2_ids(emr, cluster_id, core_id),
        lambda ids: len(ids) == _CORE_TARGET,
        timeout_s=600,
        interval_s=20,
        description=(
            f"the CORE group of {cluster_id} really grows to {_CORE_TARGET} non-terminated instances"
        ),
    )
    assert len(after_ids) == _CORE_TARGET, (
        f"the resize must yield exactly {_CORE_TARGET} non-terminated CORE instances, got "
        f"{after_ids!r}"
    )
    assert set(before_ids) < set(after_ids), (
        f"the resize must ADD a node, not replace one: the pre-resize instance(s) {before_ids!r} "
        f"must all still be present in {after_ids!r}"
    )
    added = sorted(set(after_ids) - set(before_ids))
    assert len(added) == 1, (
        f"exactly one instance must have been added by a 1 -> {_CORE_TARGET} resize, got {added!r}"
    )

    running = _poll(
        lambda: _groups(emr, cluster_id)["CORE"]["RunningInstanceCount"],
        lambda n: n == _CORE_TARGET,
        timeout_s=600,
        interval_s=20,
        description=f"the CORE group's RunningInstanceCount catches up to {_CORE_TARGET}",
    )
    assert running == _CORE_TARGET, (
        f"RunningInstanceCount must converge to {_CORE_TARGET} once the node is up, got {running!r}"
    )

    # --- THE terminal read, at EC2: a different service and a different operation than the
    # mutation. EMR's own count is not the verdict.
    def _ec2_view():
        reservations = [
            r for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=after_ids)
            for r in page["Reservations"]
        ]
        return {i["InstanceId"]: i for r in reservations for i in r["Instances"]}

    seen = _poll(
        _ec2_view,
        lambda m: len(m) == _CORE_TARGET
        and all(i["State"]["Name"] == "running" for i in m.values()),
        timeout_s=300,
        interval_s=15,
        description=f"EC2 reports all {_CORE_TARGET} CORE instances of {cluster_id} as running",
    )
    assert sorted(seen) == after_ids, (
        f"EC2 must know every instance EMR attributes to the CORE group; EMR says {after_ids!r}, "
        f"EC2 returned {sorted(seen)!r}"
    )
    for iid, inst in sorted(seen.items()):
        assert inst["State"]["Name"] == "running", (
            f"CORE instance {iid} must be running in EC2, got {inst['State']!r}"
        )
        assert inst["InstanceType"] == INSTANCE_TYPE, (
            f"CORE instance {iid} must be the requested {INSTANCE_TYPE}, EC2 reports "
            f"{inst['InstanceType']!r}"
        )
        assert inst["SubnetId"] == subnet, (
            f"CORE instance {iid} must be placed in the requested subnet {subnet!r}, EC2 reports "
            f"{inst.get('SubnetId')!r}"
        )

    # --- and the resize touched exactly one group.
    primary_after = _groups(emr, cluster_id)["MASTER"]
    assert (
        primary_after["RequestedInstanceCount"], primary_after["RunningInstanceCount"]
    ) == primary_before, (
        f"a CORE resize must not change the primary group; it was "
        f"{primary_before!r} (requested, running) and is now "
        f"{(primary_after['RequestedInstanceCount'], primary_after['RunningInstanceCount'])!r}"
    )
    primary_live = _live_ec2_ids(emr, cluster_id, primary_id)
    assert len(primary_live) == 1, (
        f"a CORE resize must not add or remove primary nodes; the primary group holds "
        f"{primary_live!r}"
    )
    assert not set(primary_live) & set(after_ids), (
        f"no instance may be attributed to both groups; primary {primary_live!r} and core "
        f"{after_ids!r} overlap"
    )


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
