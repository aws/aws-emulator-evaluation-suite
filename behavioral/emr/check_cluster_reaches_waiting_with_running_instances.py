"""cluster-reaches-waiting-with-running-instances."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cluster-reaches-waiting-with-running-instances"
GROUP = 'cluster-lifecycle'
SERVICES = ['emr']

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

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
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
# The v1 service policy, deliberately, NOT AmazonEMRServicePolicy_v2: v2 only grants EMR access
# to network resources carrying the `for-use-with-amazon-emr-managed-policies` tag, so it would make
# this check depend on the account's default VPC being pre-tagged.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

# AutoTerminationPolicy.IdleTimeout is a cost safety net, but it also governs the very resource
# this check observes: a step-less keep-alive cluster is IDLE from the instant it reaches WAITING.
# At EMR's 60s floor the cluster raced its own auto-termination, because the post-WAITING
# assertions poll list_instance_groups and list_instances with timeout_s=300 each -- so up to ~600s
# of observation against a cluster that self-terminates after 60s of idleness, failing against a
# perfectly correct backend. 900s comfortably exceeds that window; the worst case if teardown were
# ever missed is one m5.xlarge cluster for 15 minutes (~$0.08), against the cost of a false failure.
IDLE_TIMEOUT_S = 900

MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}


def _swallow(fn):
    """Run fn(), swallowing any exception. Teardown-only — never an assertion."""
    try:
        fn()
    except Exception:  # noqa: BLE001 — best-effort teardown
        pass


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = _teardown_deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cluster_state(emr, cluster_id):
    return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]


def _register_cluster_cleanup(ctx, emr, cluster_id) -> None:
    """Register teardown for cluster_id. MUST be called before the id is used.

    Termination protection blocks TerminateJobFlows outright, so it is cleared
    first; termination is then polled to a terminal state (EMR keeps the EC2
    fleet and any referenced security configuration / log bucket pinned until the
    cluster is actually TERMINATED, so a fire-and-forget terminate would make
    every later cleanup fail and leak the fleet).
    """

    def _cleanup() -> None:
        _swallow(
            lambda: emr.set_termination_protection(
                JobFlowIds=[cluster_id], TerminationProtected=False
            )
        )
        _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
        _poll(
            lambda: _cluster_state(emr, cluster_id),
            lambda s: s in TERMINAL_CLUSTER_STATES,
            timeout_s=600,
            interval_s=2,
            description=f"cluster {cluster_id} reaches a terminal state", ctx=ctx
        )

    ctx.on_cleanup(_cleanup)


def _delete_with_retry(fn, attempts=6, delay=10, ctx=None):
    """Run an IAM delete, retrying DeleteConflict.

    Even once the cluster reports TERMINATED, IAM can briefly still see the instance
    profile as in use. The runner swallows teardown errors, so without a retry the only
    symptom of losing that race would be a leaked role nobody looks at.
    """
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1 or _cleanup_spent(ctx):
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the service role and EC2 instance profile EMR needs, and register their
    teardown. Returns (service_role, ec2_role)."""

    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-ec2-")
    # Cleanups run LIFO, so registering each teardown immediately after its create yields the
    # only order IAM accepts: remove-from-profile, delete profile, detach policies, delete roles.
    try:
        iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role), ctx=ctx))
        iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

        iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role), ctx=ctx))
        iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

        # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name; give it the
        # same name as its role, which is the convention EMR's own default roles follow.
        iam.create_instance_profile(InstanceProfileName=ec2_role)
        ctx.on_cleanup(lambda: _delete_with_retry(
            lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role), ctx=ctx))
        iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=ec2_role, RoleName=ec2_role))
    except Exception as exc:  # noqa: BLE001
        # Can't attribute anything to EMR if we couldn't even build its prerequisites — an
        # honest skip, not a mystery RunJobFlow ValidationException.
        raise AssertionError(
            f"cannot provision the EMR service role / EC2 instance profile: {exc}"
        ) from exc

    # IAM is eventually consistent; EMR rejects a role/profile it cannot see yet. RunJobFlow
    # also retries "invalid InstanceProfile" below, so this bounded poll only shortens that
    # retry loop -- it never gates correctness, hence the swallow.
    _swallow(lambda: _poll(
        lambda: iam.get_instance_profile(InstanceProfileName=ec2_role),
        lambda r: bool(r["InstanceProfile"]["Roles"]),
        timeout_s=60,
        interval_s=5,
        description=f"instance profile {ec2_role} becomes visible to IAM reads",
    ))
    return svc_role, ec2_role


def _launch_cluster(
    ctx, emr, *, keep_alive: bool, service_role: str, job_flow_role: str, steps=None, **overrides
):
    """RunJobFlow the cheapest cluster that can prove a data-plane invariant.

    One m5.xlarge primary group and NO core/task group — EMR runs the whole job on
    the primary when no core group is requested, which is the minimum billable
    shape. Cost guards: Tags at creation (propagate to the EC2 instances),
    AutoTerminationPolicy so an abandoned cluster self-terminates, and
    KeepJobFlowAliveWhenNoSteps=False whenever the invariant allows it.
    """
    name = ctx.unique_name("sim2real-behav-emr-cluster-")
    params = dict(
        Name=name,
        ReleaseLabel=RELEASE_LABEL,
        Instances={
            "Ec2SubnetId": _private_network(ctx, INSTANCE_TYPE)[1],
            "InstanceGroups": [
                {
                    "Name": "Primary",
                    "InstanceRole": "MASTER",
                    "InstanceType": INSTANCE_TYPE,
                    "InstanceCount": 1,
                    "Market": "ON_DEMAND",
                }
            ],
            "KeepJobFlowAliveWhenNoSteps": keep_alive,
            "TerminationProtected": False,
        },
        Applications=[{"Name": "Hadoop"}],
        JobFlowRole=job_flow_role,
        ServiceRole=service_role,
        VisibleToAllUsers=True,
        Tags=MANAGED_TAGS,
        AutoTerminationPolicy={"IdleTimeout": IDLE_TIMEOUT_S},
    )
    if steps is not None:
        params["Steps"] = steps
    params.update(overrides)

    # EMR_EC2_DefaultRole's instance profile is eventually consistent right after
    # the default roles are created, and RunJobFlow is throttled aggressively.
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = _run_job_flow_propagated(ctx, emr, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            lowered = str(exc).lower()
            transient = (
                "throttl" in lowered
                or "rate exceeded" in lowered
                or "invalid instanceprofile" in lowered
                or "invalid ec2" in lowered
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)

    cluster_id = resp["JobFlowId"]
    _register_cluster_cleanup(ctx, emr, cluster_id)  # BEFORE the id is used anywhere
    return cluster_id, name


# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A launched EMR cluster actually boots: it reaches WAITING with a real EC2 fleet RUNNING
    behind it, a resolvable primary DNS name and a ReadyDateTime, not parked in STARTING."""
    emr = ctx.client("emr")
    # Registered first, so LIFO tears the cluster down before the IAM roles it assumes.
    service_role, job_flow_role = _ensure_emr_roles(ctx)

    # KeepJobFlowAliveWhenNoSteps=True is required: with no steps and no keep-alive
    # the cluster self-terminates the instant it is ready and WAITING is unobservable.
    # The AutoTerminationPolicy (60s idle) is what bounds the cost of that.
    cluster_id, name = _launch_cluster(
        ctx, emr, keep_alive=True, service_role=service_role, job_flow_role=job_flow_role
    )

    state = _poll(
        lambda: _cluster_state(emr, cluster_id),
        lambda s: s in TERMINAL_CLUSTER_STATES | {"WAITING", "RUNNING"},
        timeout_s=1500,
        interval_s=20,
        description=f"cluster {cluster_id} leaves the provisioning states",
    )
    assert state == "WAITING", (
        f"a step-less keep-alive cluster must provision to WAITING, got {state!r} "
        f"(reason: "
        f"{emr.describe_cluster(ClusterId=cluster_id)['Cluster']['Status'].get('StateChangeReason')!r})"
    )

    cluster = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    assert cluster["Name"] == name, f"DescribeCluster echoed {cluster['Name']!r}, expected {name!r}"

    # A cluster that really booted has a primary node with a resolvable hostname.
    dns = cluster.get("MasterPublicDnsName") or ""
    assert dns, "a WAITING cluster must report MasterPublicDnsName; got an empty/absent value"
    assert "." in dns, f"MasterPublicDnsName must be a hostname, got {dns!r}"

    # ReadyDateTime is only set once the fleet is up, and must not precede creation.
    timeline = cluster["Status"]["Timeline"]
    assert "ReadyDateTime" in timeline, (
        f"a WAITING cluster must carry Status.Timeline.ReadyDateTime, got {timeline!r}"
    )
    assert timeline["ReadyDateTime"] >= timeline["CreationDateTime"], (
        f"ReadyDateTime {timeline['ReadyDateTime']} precedes "
        f"CreationDateTime {timeline['CreationDateTime']}"
    )

    # The requested instance group must actually be RUNNING with its instances up.
    groups = _poll(
        lambda: emr.list_instance_groups(ClusterId=cluster_id)["InstanceGroups"],
        lambda gs: bool(gs) and all(g["Status"]["State"] == "RUNNING" for g in gs),
        timeout_s=300,
        interval_s=15,
        description=f"cluster {cluster_id} instance groups reach RUNNING",
    )
    assert len(groups) == 1, f"expected exactly the one requested MASTER group, got {groups!r}"
    primary = groups[0]
    assert primary["InstanceGroupType"] == "MASTER", (
        f"the only group must be MASTER, got {primary['InstanceGroupType']!r}"
    )
    assert primary["RunningInstanceCount"] == 1, (
        f"RunningInstanceCount must converge to the requested 1, got "
        f"{primary['RunningInstanceCount']!r}"
    )

    # ...and a real EC2 instance must be behind it.
    instances = _poll(
        lambda: emr.list_instances(ClusterId=cluster_id, InstanceGroupId=primary["Id"])["Instances"],
        lambda ins: any(i["Status"]["State"] == "RUNNING" for i in ins),
        timeout_s=300,
        interval_s=15,
        description=f"cluster {cluster_id} reports a RUNNING instance",
    )
    running = [i for i in instances if i["Status"]["State"] == "RUNNING"]
    assert len(running) == 1, f"expected 1 RUNNING instance, got {len(running)}: {instances!r}"
    inst = running[0]
    assert inst.get("Ec2InstanceId", "").startswith("i-"), (
        f"a RUNNING EMR instance must name its EC2 instance (i-...), got "
        f"{inst.get('Ec2InstanceId')!r}"
    )
    assert inst.get("InstanceType") == INSTANCE_TYPE, (
        f"instance type must be the requested {INSTANCE_TYPE}, got {inst.get('InstanceType')!r}"
    )
    assert inst.get("PrivateIpAddress"), (
        f"a RUNNING EMR instance must report a PrivateIpAddress, got {inst!r}"
    )

    # Billing is measured, not zero, once a cluster has actually run.
    assert cluster.get("NormalizedInstanceHours") is not None, (
        "DescribeCluster must report NormalizedInstanceHours for a cluster that ran"
    )


def _run_job_flow_propagated(ctx, emr, **params):
    """RunJobFlow, retrying every 2 s while IAM has not yet propagated a new instance profile to EMR
    ("Failed to authorize instance profile"), to min(180 s, the check's time left); raises the rest."""
    from botocore.exceptions import ClientError

    left = None if ctx is None else ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    while True:
        try:
            return emr.run_job_flow(**params)
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "AccessDeniedException"
                           and "failed to authorize instance profile" in err.get("Message", "").lower())
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
