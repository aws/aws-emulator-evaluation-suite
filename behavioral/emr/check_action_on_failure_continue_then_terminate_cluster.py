"""action-on-failure-continue-then-terminate-cluster."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "action-on-failure-continue-then-terminate-cluster"
GROUP = 'steps'
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
# to network resources carrying the `for-use-with-amazon-emr-managed-policies` tag, which the
# check's own VPC does not carry.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
IDLE_TIMEOUT_S = 60

MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}


def _swallow(fn):
    """Run a teardown call fn(), tolerating only a cluster that is gone or already shut down."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            not (err["Code"] == "InvalidRequestException" and "is not valid" in err.get("Message", ""))
            and not (err["Code"] == "ValidationException" and "Specified job flow ID not valid" in err.get("Message", ""))
            and not (err["Code"] == "ValidationException" and "may not be modified" in err.get("Message", ""))
        ):
            raise


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
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
    """Register teardown for cluster_id. MUST be called before the id is used."""

    def _cleanup() -> None:
        _swallow(
            lambda: emr.set_termination_protection(
                JobFlowIds=[cluster_id], TerminationProtected=False
            )
        )
        _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
        _swallow(
            lambda: _poll(
                lambda: _cluster_state(emr, cluster_id),
                lambda s: s in TERMINAL_CLUSTER_STATES,
                timeout_s=600,
                interval_s=2,
                description=f"cluster {cluster_id} reaches a terminal state",
            )
        )

    ctx.on_cleanup(_cleanup)


def _delete_with_retry(fn, attempts=6, delay=10):
    """Run an IAM delete, retrying DeleteConflict.

    Even once the cluster reports TERMINATED, IAM can briefly still see the instance
    profile as in use, so the delete is retried rather than leaking the role.
    """
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
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
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
        iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

        iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
        iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

        # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name; give it the
        # same name as its role, which is the convention EMR's own default roles follow.
        iam.create_instance_profile(InstanceProfileName=ec2_role)
        ctx.on_cleanup(lambda: _delete_with_retry(
            lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
        iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=ec2_role, RoleName=ec2_role))
    except Exception as exc:  # noqa: BLE001
        # Can't attribute anything to EMR if we couldn't even build its prerequisites — an
        # honest skip, not a mystery RunJobFlow ValidationException.
        raise AssertionError(
            f"cannot provision the EMR service role / EC2 instance profile: {exc}"
        ) from exc

    # IAM is eventually consistent and EMR rejects a role/profile it cannot see yet. No IAM read
    # observes EMR-side visibility, so there is no predicate to poll here -- the bounded retry in
    # _launch_cluster below (on "invalid instanceprofile" / "invalid ec2") is the actual wait, with
    # a deadline and a stated reason; this function does not need an unconditional sleep on top of
    # it.
    return svc_role, ec2_role


def _launch_cluster(
    ctx, emr, *, keep_alive: bool, service_role: str, job_flow_role: str, steps=None, **overrides
):
    """RunJobFlow the cheapest cluster that can prove a data-plane invariant."""
    name = ctx.unique_name("sim2real-behav-emr-cluster-")
    params = dict(
        Name=name,
        ReleaseLabel=RELEASE_LABEL,
        Instances={
            "InstanceGroups": [
                {
                    "Name": "Primary",
                    "InstanceRole": "MASTER",
                    "InstanceType": INSTANCE_TYPE,
                    "InstanceCount": 1,
                    "Market": "ON_DEMAND",
                }
            ],
            "Ec2SubnetId": _private_network(ctx, INSTANCE_TYPE)[1],
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

    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(**params)
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


def _shell_step(name, exit_code, action_on_failure):
    """A step that does nothing but exit with exit_code, via the YARN step runner."""
    return {
        "Name": name,
        "ActionOnFailure": action_on_failure,
        "HadoopJarStep": {
            "Jar": "command-runner.jar",
            "Args": ["bash", "-c", f"exit {exit_code}"],
        },
    }


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ActionOnFailure dispatch: CONTINUE lets the next step run after a failure, TERMINATE_CLUSTER
    ends the cluster TERMINATED_WITH_ERRORS (STEP_FAILURE) and CANCELS the pending step, and steps
    run strictly in sequence at StepConcurrencyLevel=1."""
    emr = ctx.client("emr")
    # Registered first, so LIFO tears the cluster down before the IAM roles it assumes.
    service_role, job_flow_role = _ensure_emr_roles(ctx)

    submitted = [
        _shell_step("sim2real-behav-emr-fail-continue", 3, "CONTINUE"),
        _shell_step("sim2real-behav-emr-ok-after-continue", 0, "CONTINUE"),
        _shell_step("sim2real-behav-emr-fail-terminate", 4, "TERMINATE_CLUSTER"),
        _shell_step("sim2real-behav-emr-never-runs", 0, "CONTINUE"),
    ]

    # keep_alive=True so the only thing that can terminate this cluster is step 3's
    # TERMINATE_CLUSTER — with keep_alive=False an ALL_STEPS_COMPLETED shutdown
    # would be indistinguishable from the STEP_FAILURE one being asserted.
    # StepConcurrencyLevel=1 is stated explicitly rather than relying on the default,
    # because the sequential-ordering assertion below depends on it.
    cluster_id, _ = _launch_cluster(
        ctx,
        emr,
        keep_alive=True,
        service_role=service_role,
        job_flow_role=job_flow_role,
        steps=submitted,
        StepConcurrencyLevel=1,
    )

    # ListSteps is newest-first, so reverse it to get submission order.
    listed = emr.list_steps(ClusterId=cluster_id)["Steps"]
    assert len(listed) == 4, f"expected the 4 submitted steps, got {len(listed)}: {listed!r}"
    in_submission_order = list(reversed(listed))
    names = [s["Name"] for s in in_submission_order]
    assert names == [s["Name"] for s in submitted], (
        f"ListSteps reversed must be submission order, got {names!r}"
    )
    step_ids = [s["Id"] for s in in_submission_order]

    final_cluster = _poll(
        lambda: _cluster_state(emr, cluster_id),
        lambda s: s in TERMINAL_CLUSTER_STATES,
        timeout_s=2400,
        interval_s=30,
        description=f"cluster {cluster_id} reaches a terminal state",
    )

    def _steps():
        return [
            emr.describe_step(ClusterId=cluster_id, StepId=sid)["Step"] for sid in step_ids
        ]

    # The step view lags the cluster's terminal state by a polling interval.
    described = _poll(
        _steps,
        lambda ss: all(
            s["Status"]["State"] in {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
            for s in ss
        ),
        timeout_s=300,
        interval_s=15,
        description=f"all 4 steps of {cluster_id} reach a terminal state",
    )
    states = [s["Status"]["State"] for s in described]

    assert states[0] == "FAILED", f"step 1 (exit 3) must be FAILED, got {states[0]!r}"
    # FailureDetails is not asserted: EMR documents it as a best-effort diagnostic, and a step that
    # only exits non-zero under command-runner.jar publishes none. The causal-ordering assertions
    # below bind ActionOnFailure instead.
    assert states[1] == "COMPLETED", (
        f"ActionOnFailure=CONTINUE must let step 2 run after step 1 failed; "
        f"step 2 is {states[1]!r} (all states: {states!r})"
    )
    assert states[2] == "FAILED", f"step 3 (exit 4) must be FAILED, got {states[2]!r}"
    assert states[3] == "CANCELLED", (
        f"ActionOnFailure=TERMINATE_CLUSTER must CANCEL the still-pending step 4; "
        f"got {states[3]!r} (all states: {states!r})"
    )

    assert final_cluster == "TERMINATED_WITH_ERRORS", (
        f"a TERMINATE_CLUSTER step failure must end the cluster in "
        f"TERMINATED_WITH_ERRORS, got {final_cluster!r}"
    )
    cluster_status = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]

    # The shutdown must be CAUSED by step 3, not merely coincident with it: the terminating step
    # has to have finished, and the cluster's end must not precede it. An emulator that terminates
    # the cluster as soon as it sees ActionOnFailure=TERMINATE_CLUSTER (before running the step to
    # its end) reports the same states but fails this ordering.
    terminating_end = described[2]["Status"]["Timeline"].get("EndDateTime")
    assert terminating_end is not None, (
        f"the TERMINATE_CLUSTER step must carry EndDateTime, got "
        f"{described[2]['Status']['Timeline']!r}"
    )
    cluster_end = cluster_status["Timeline"].get("EndDateTime")
    assert cluster_end is not None, (
        f"a terminated cluster must carry Timeline.EndDateTime, got {cluster_status!r}"
    )
    assert cluster_end >= terminating_end, (
        f"the cluster ended at {cluster_end} but the step that terminated it only finished at "
        f"{terminating_end} — the shutdown cannot precede its own cause"
    )

    reason = cluster_status["StateChangeReason"]
    assert reason.get("Code") == "STEP_FAILURE", (
        f"a cluster terminated by a failing step must report StateChangeReason.Code "
        f"STEP_FAILURE, got {reason!r}"
    )
    assert reason.get("Message"), (
        f"StateChangeReason must carry a human-readable Message, got {reason!r}"
    )

    # Sequential execution at StepConcurrencyLevel=1: step N ends before step N+1
    # starts. Asserted as a SEQUENCE over the executed prefix (steps 1-3), never a set.
    executed = described[:3]
    for i in range(len(executed) - 1):
        end = executed[i]["Status"]["Timeline"].get("EndDateTime")
        nxt = executed[i + 1]["Status"]["Timeline"].get("StartDateTime")
        assert end is not None, (
            f"executed step {i + 1} must carry EndDateTime, got "
            f"{executed[i]['Status']['Timeline']!r}"
        )
        assert nxt is not None, (
            f"executed step {i + 2} must carry StartDateTime, got "
            f"{executed[i + 1]['Status']['Timeline']!r}"
        )
        assert end <= nxt, (
            f"at StepConcurrencyLevel=1 step {i + 1} must finish ({end}) before step "
            f"{i + 2} starts ({nxt}) — steps overlapped"
        )

    # The cancelled step never ran at all — no timeline at EITHER end. Asserting only the absence
    # of StartDateTime would still pass for an emulator that stamps an EndDateTime on cancellation,
    # which would mean the step was accounted for as having executed.
    cancelled_timeline = described[3]["Status"]["Timeline"]
    assert "StartDateTime" not in cancelled_timeline, (
        f"a CANCELLED, never-dispatched step must have no StartDateTime, got "
        f"{cancelled_timeline!r}"
    )
    assert "EndDateTime" not in cancelled_timeline, (
        f"a CANCELLED, never-dispatched step must have no EndDateTime either, got "
        f"{cancelled_timeline!r}"
    )
    assert cancelled_timeline.get("CreationDateTime") is not None, (
        f"a CANCELLED step must still record when it was SUBMITTED, got {cancelled_timeline!r}"
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
