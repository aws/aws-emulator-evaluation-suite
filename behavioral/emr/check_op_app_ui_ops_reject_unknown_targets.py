"""op-app-ui-ops-reject-unknown-targets."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]

CHECK = "op-app-ui-ops-reject-unknown-targets"
GROUP = 'overly-permissive'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

UNKNOWN_CLUSTER_ID = "j-" + "Z" * 13

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

SUCCEEDED = "<call succeeded>"


def _code_or_success(fn):
    """Invoke *fn*; return the error code on rejection, or ``SUCCEEDED`` (a value no
    error code can equal) on success -- for positive controls where success is itself
    an acceptable outcome."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__)
    return SUCCEEDED

def _assert_codes(cases: dict, expected: str, expected_messages: dict[str, str] | None = None) -> None:
    """Assert every (label -> thunk) in *cases* is rejected with *expected* code and,
    when *expected_messages* is given, with exactly that op's message."""
    results = {label: _error_stable(thunk) for label, thunk in cases.items()}
    wrong = {label: code for label, (code, _msg) in results.items() if code != expected}
    assert not wrong, f"expected {expected} for every op, got mismatches: {wrong}"
    if expected_messages is not None:
        mismatched = {
            label: msg
            for label, (_code, msg) in results.items()
            if msg != expected_messages[label]
        }
        assert not mismatched, f"unexpected rejection message(s): {mismatched}"

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

def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """App-UI ops reject unknown clusters (ValidationException, exact messages) and an unknown
    PersistentAppUIId (InvalidRequestException), while the same ops accept a real cluster.
    """
    emr = ctx.client("emr")
    cluster_id = _launch_cluster(ctx)

    # A real but not-yet-runnable cluster answers InvalidRequestException (wrong state),
    # never the ValidationException reserved for an id that was never valid.
    positive_on_cluster_code = _code_or_success(
        lambda: emr.get_on_cluster_app_ui_presigned_url(
            ClusterId=cluster_id, OnClusterAppUIType="SparkHistoryServer", DryRun=True
        )
    )
    assert positive_on_cluster_code != "ValidationException", (
        "GetOnClusterAppUIPresignedURL against a real, still-active cluster id was "
        f"rejected as an invalid id ({positive_on_cluster_code!r}); the check can no longer "
        "tell an unknown ClusterId apart from a real one"
    )

    cluster_arn = _terminate_and_get_arn(ctx, cluster_id)

    created = emr.create_persistent_app_ui(TargetResourceArn=cluster_arn)
    ui_id = created["PersistentAppUIId"]
    assert ui_id, "CreatePersistentAppUI against a real cluster ARN returned no id"

    described = emr.describe_persistent_app_ui(PersistentAppUIId=ui_id)["PersistentAppUI"]
    assert described["PersistentAppUIId"] == ui_id, (
        f"positive-control describe returned {described.get('PersistentAppUIId')!r}, expected {ui_id!r}"
    )

    unknown_arn = f"arn:aws:elasticmapreduce:{ctx.region}:{_account_id(ctx)}:cluster/{UNKNOWN_CLUSTER_ID}"
    _assert_codes(
        {
            "CreatePersistentAppUI": lambda: emr.create_persistent_app_ui(
                TargetResourceArn=unknown_arn
            ),
            "GetOnClusterAppUIPresignedURL": lambda: emr.get_on_cluster_app_ui_presigned_url(
                ClusterId=UNKNOWN_CLUSTER_ID
            ),
        },
        "ValidationException",
        expected_messages={
            "CreatePersistentAppUI": "Cluster id is not valid.",
            "GetOnClusterAppUIPresignedURL": f"Cluster id '{UNKNOWN_CLUSTER_ID}' is not valid.",
        },
    )
    # DescribePersistentAppUI's message embeds a per-call request id.
    unknown_ui = "p-" + "Z" * 13
    code, message = _error_stable(lambda: emr.describe_persistent_app_ui(PersistentAppUIId=unknown_ui))
    assert code == "InvalidRequestException", f"DescribePersistentAppUI: expected InvalidRequestException, got {code}"
    expected = _service_message(f"PersistentAppUI with ID '{unknown_ui}' does not exist", message, "EMRProfilers")
    assert message == expected, f"DescribePersistentAppUI: expected the message {expected!r}, got {message!r}"

    # The real PersistentAppUI is untouched by the negative calls.
    still_described = emr.describe_persistent_app_ui(PersistentAppUIId=ui_id)["PersistentAppUI"]
    assert still_described["PersistentAppUIId"] == ui_id, (
        f"positive-control PersistentAppUI {ui_id!r} stopped being describable after the "
        "negative calls ran"
    )



_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"


def _trust_policy(service):
    return json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    )


def _ensure_emr_roles(ctx):
    """Create this check's own EMR roles; the default roles exist only after
    `aws emr create-default-roles`."""
    iam = ctx.client("iam")
    svc_name = ctx.unique_name("sim2real-emrsvc-")
    ec2_name = ctx.unique_name("sim2real-emrec2-")

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=_trust_policy("elasticmapreduce.amazonaws.com"))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    iam.attach_role_policy(RoleName=svc_name, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_name, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=_trust_policy("ec2.amazonaws.com"))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn=_EC2_POLICY))
    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))
    return svc_name, ec2_name


def _default_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _run_job_flow_with_retry(emr, timeout_s=120.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            if "role" in msg or "profile" in msg or "not authorized" in msg:
                last_err = exc
                time.sleep(2)
                continue
            raise
    raise last_err


def _wait_for_cluster_state(ctx, cluster_id, target_states, timeout_s=600.0, interval_s=15.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_states}, last state {state}")


def _launch_cluster(ctx):
    emr = ctx.client("emr")
    # Roles before the network: cleanup runs LIFO, so the network teardown, which waits for the
    # cluster to terminate, finishes before the roles EMR needs to terminate it are deleted.
    svc_role, ec2_role = _ensure_emr_roles(ctx)
    subnet_id = _default_subnet(ctx)
    resp = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-appui-"),
        ReleaseLabel="emr-6.15.0",
        Instances={
            "InstanceCount": 1,
            "MasterInstanceType": "m5.xlarge",
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        JobFlowRole=ec2_role,
        ServiceRole=svc_role,
        VisibleToAllUsers=True,
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id


def _terminate_and_get_arn(ctx, cluster_id):
    emr = ctx.client("emr")
    cluster_arn = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["ClusterArn"]
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    _wait_for_cluster_state(ctx, cluster_id, {"TERMINATED", "TERMINATED_WITH_ERRORS"}, timeout_s=600)
    return cluster_arn


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
