"""op-jobflow-style-ops-reject-unknown-cluster."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

CHECK = "op-jobflow-style-ops-reject-unknown-cluster"
GROUP = 'overly-permissive'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

UNKNOWN_CLUSTER_ID = "j-" + "Z" * 13

UNKNOWN_GROUP_ID = "ig-" + "Z" * 13

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
# Deliberately not AmazonEMRServicePolicy_v2, which requires the VPC to carry the
# `for-use-with-amazon-emr-managed-policies` tag.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"


def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _default_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _delete_with_retry(fn, attempts=6, delay=10):
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and EC2 instance profile; the default roles exist only after
    `aws emr create-default-roles`."""
    iam = ctx.client("iam")
    svc_role = _unique_name("emr-svc-")
    ec2_role = _unique_name("emr-ec2-")
    # Cleanups run LIFO; registering each teardown right after its create gives the only order IAM
    # accepts: remove-from-profile, delete profile, detach policies, delete roles.
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM is eventually consistent; _run_basic_cluster retries "invalid instanceprofile".
    return svc_role, ec2_role


_CLUSTER_GONE_CODES = ("InvalidRequestException", "ClusterNotFound",
                       "ResourceNotFoundException", "EntityNotFoundException")


def _cluster_is_gone(exc):
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc) or "does not exist" in str(exc)


def _terminate_and_await_teardown(ctx, emr, cluster_id):
    """Terminate and WAIT before returning, so the IAM role deletions queued behind this cleanup
    (LIFO) never fire while EMR still needs those roles to wind the cluster down."""
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    deadline = min(time.monotonic() + 540, _cleanup_deadline(ctx))
    last_state = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            last_state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001
            if _cluster_is_gone(exc):
                return
            last_exc = exc
            time.sleep(2)
            continue
        if last_state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id} did not terminate within 540s, last state {last_state!r}, "
        f"last describe error {last_exc!r}"
    )


def _run_basic_cluster(emr, ctx, service_role, job_flow_role):
    name = _unique_name("emr-cluster-")
    params = dict(
        Name=name,
        ReleaseLabel=RELEASE_LABEL,
        Instances={
            # AddInstanceGroups rejects a primary-only job flow with ValidationException, so the
            # positive control needs a CORE group.
            "InstanceGroups": [
                {"Name": "Primary", "InstanceRole": "MASTER",
                 "InstanceType": INSTANCE_TYPE, "InstanceCount": 1},
                {"Name": "Core", "InstanceRole": "CORE",
                 "InstanceType": INSTANCE_TYPE, "InstanceCount": 1},
            ],
            "Ec2SubnetId": _default_subnet(ctx),
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        ServiceRole=service_role,
        JobFlowRole=job_flow_role,
        VisibleToAllUsers=True,
        Applications=[{"Name": "Hadoop"}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    left = ctx.time_left()
    deadline = time.monotonic() + (320.0 if left is None else min(320.0, left))
    while True:
        try:
            resp = emr.run_job_flow(**params)
            break
        except Exception as exc:  # noqa: BLE001
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
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, emr, cluster_id))
    return cluster_id


def _expect_success(fn, attempts=10, delay=15):
    """Run a positive-control call on the real cluster, retrying throttling and not-yet-ready
    states a bounded number of times; raise if it never succeeds."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            lowered = str(exc).lower()
            transient = (
                "throttl" in lowered
                or "rate exceeded" in lowered
                or "is not in a valid state" in lowered
            )
            if not transient or attempt == attempts - 1:
                raise AssertionError(
                    "expected the positive control to succeed against a real, live cluster, "
                    f"got {exc!r}"
                ) from exc
            last_exc = exc
            time.sleep(delay)
    raise AssertionError(f"positive control never succeeded: {last_exc}")

_ACTIVE_STATES = ("RUNNING", "WAITING")


def _await_active(emr, cluster_id, timeout_s=900):
    """Bounded wait for RUNNING or WAITING; ModifyInstanceGroups is rejected until then."""
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in _ACTIVE_STATES:
            return state
        if _cluster_is_gone_state(state):
            raise AssertionError(
                f"cluster {cluster_id} reached {state!r} before ever becoming RUNNING/WAITING"
            )
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id} did not reach RUNNING/WAITING within {timeout_s}s, last state {state!r}"
    )


def _cluster_is_gone_state(state):
    return state in ("TERMINATED", "TERMINATED_WITH_ERRORS")



def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

def _assert_rejections(cases: dict, expected: dict[str, tuple[str, str]]) -> None:
    """Assert every (label -> thunk) in *cases* is rejected with exactly the (code, message) in
    *expected[label]*."""
    actual = {label: _error_stable(thunk) for label, thunk in cases.items()}
    wrong = {k: v for k, v in actual.items() if v != expected[k]}
    assert not wrong, f"expected {expected} for every op, got mismatches: {wrong}"

def _error_stable(fn, attempts: int = 6):
    """Like ``_error`` but retries through throttling so the assertion observes
    the operation's real rejection code rather than a rate-limit artefact."""
    code, message = _error(fn)
    for attempt in range(attempts - 1):
        if code not in THROTTLE_CODES:
            break
        time.sleep(5 * (attempt + 1))
        code, message = _error(fn)
    return code, message

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The seven JobFlow-style mutations reject an unknown cluster with ValidationException (not
    InvalidRequestException) and exact messages, after all succeed on a real, live cluster.
    """
    emr = ctx.client("emr")
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    real_id = _run_basic_cluster(emr, ctx, service_role, job_flow_role)

    _expect_success(lambda: emr.set_visible_to_all_users(
        JobFlowIds=[real_id], VisibleToAllUsers=False))
    _expect_success(lambda: emr.set_keep_job_flow_alive_when_no_steps(
        JobFlowIds=[real_id], KeepJobFlowAliveWhenNoSteps=True))
    _expect_success(lambda: emr.set_termination_protection(
        JobFlowIds=[real_id], TerminationProtected=True))
    _expect_success(lambda: emr.set_termination_protection(
        JobFlowIds=[real_id], TerminationProtected=False))
    _expect_success(lambda: emr.add_job_flow_steps(
        JobFlowId=real_id,
        Steps=[
            {
                "Name": "positive-control-step",
                "ActionOnFailure": "CONTINUE",
                "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["true"]},
            }
        ],
    ))
    group_resp = _expect_success(lambda: emr.add_instance_groups(
        JobFlowId=real_id,
        InstanceGroups=[
            {
                "Name": "Task",
                "InstanceRole": "TASK",
                "InstanceType": INSTANCE_TYPE,
                "InstanceCount": 1,
            }
        ],
    ))
    real_group_id = group_resp["InstanceGroupIds"][0]
    # "An instance group may only be modified when the cluster is running or waiting."
    _await_active(emr, real_id)
    _expect_success(lambda: emr.modify_instance_groups(
        ClusterId=real_id,
        InstanceGroups=[{"InstanceGroupId": real_group_id, "InstanceCount": 1}],
    ))
    _expect_success(lambda: emr.terminate_job_flows(JobFlowIds=[real_id]))

    j = UNKNOWN_CLUSTER_ID
    job_flow_invalid = "Specified job flow ID not valid."
    _assert_rejections(
        {
            "TerminateJobFlows": lambda: emr.terminate_job_flows(JobFlowIds=[j]),
            "SetTerminationProtection": lambda: emr.set_termination_protection(
                JobFlowIds=[j], TerminationProtected=True
            ),
            "SetVisibleToAllUsers": lambda: emr.set_visible_to_all_users(
                JobFlowIds=[j], VisibleToAllUsers=False
            ),
            "SetKeepJobFlowAliveWhenNoSteps": lambda: emr.set_keep_job_flow_alive_when_no_steps(
                JobFlowIds=[j], KeepJobFlowAliveWhenNoSteps=True
            ),
            "AddJobFlowSteps": lambda: emr.add_job_flow_steps(
                JobFlowId=j,
                Steps=[
                    {
                        "Name": "orphan-step",
                        "ActionOnFailure": "CONTINUE",
                        "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["true"]},
                    }
                ],
            ),
            "AddInstanceGroups": lambda: emr.add_instance_groups(
                JobFlowId=j,
                InstanceGroups=[
                    {
                        "Name": "Task",
                        "InstanceRole": "TASK",
                        "InstanceType": INSTANCE_TYPE,
                        "InstanceCount": 1,
                    }
                ],
            ),
            "ModifyInstanceGroups": lambda: emr.modify_instance_groups(
                ClusterId=j,
                InstanceGroups=[{"InstanceGroupId": UNKNOWN_GROUP_ID, "InstanceCount": 2}],
            ),
        },
        {
            "TerminateJobFlows": ("ValidationException", job_flow_invalid),
            "SetTerminationProtection": ("ValidationException", job_flow_invalid),
            "SetVisibleToAllUsers": ("ValidationException", f"Job flow id '{j}' is not valid."),
            "SetKeepJobFlowAliveWhenNoSteps": ("ValidationException", job_flow_invalid),
            "AddJobFlowSteps": ("ValidationException", job_flow_invalid),
            "AddInstanceGroups": ("ValidationException", job_flow_invalid),
            "ModifyInstanceGroups": ("ValidationException", f"Cluster id '{j}' is not valid."),
        },
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
