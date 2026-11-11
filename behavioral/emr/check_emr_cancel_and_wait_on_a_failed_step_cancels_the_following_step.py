"""emr-cancel-and-wait-on-a-failed-step-cancels-the-following-step."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-cancel-and-wait-on-a-failed-step-cancels-the-following-step"
GROUP = 'steps'
SERVICES = ['emr']

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

_SCENARIO = "emr-cancel-and-wait"
_TAGS = [{"Key": "sim2real", "Value": _SCENARIO},
         {"Key": "sim2real:managed", "Value": "true"},
         {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_EC2_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
# The v1 service policy, deliberately, NOT AmazonEMRServicePolicy_v2: v2 only grants EMR
# access to network resources carrying the `for-use-with-amazon-emr-managed-policies` tag, so it
# would make this check depend on the account's default VPC being pre-tagged.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
# Grants the cluster's EC2 instances S3 access, which is what lets the steps below write their
# markers -- the observable side effect the whole check turns on.
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_STEP_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED",
                  "TERMINATED_WITH_ERRORS", "INTERNAL_ERROR"}
_CLUSTER_GONE_CODES = ("InvalidRequestException", "ClusterNotFound",
                       "ResourceNotFoundException", "EntityNotFoundException")


def _swallow(fn):
    """Run a teardown call fn(), tolerating only a cluster or bucket that is gone or shut down."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        msg = err.get("Message", "")
        if not (err["Code"] == "NoSuchBucket" or (err["Code"] == "ValidationException" and (
                "Specified job flow ID not valid" in msg or "may not be modified" in msg))):
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


def _delete_with_retry(fn, attempts=8, delay=15, ctx=None):
    """Run an IAM delete, retrying DeleteConflict.

    Even once the cluster reports TERMINATED, IAM can briefly still see the instance profile as
    in use. Teardown errors are swallowed by the runner, so without this retry the only symptom
    of losing that race would be a leaked role nobody looks at.
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
    """Create the EMR service role and the EC2 instance profile. Returns (service_role, ec2_role).

    Created in-check and deleted on teardown: EMR_DefaultRole and
    EMR_EC2_DefaultRole do NOT exist in a fresh account, so
    pointing at them would surface as an untagged ClientError rather than as EMR behaviour.
    Cleanups are registered immediately after each create, so LIFO yields the only order IAM
    accepts: remove-from-profile, delete profile, detach policies, delete roles.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-caw-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-caw-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role), ctx=ctx))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role), ctx=ctx))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name.
    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role), ctx=ctx))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM is eventually consistent and EMR rejects a role/profile it cannot see yet. No IAM read
    # observes EMR-side visibility, so there is no predicate to poll here -- the bounded retry in
    # _run_cluster below (on "invalid instanceprofile" / "invalid ec2") is the actual wait, with a
    # deadline and a stated reason; this function does not need its own sleep on top of it.
    return svc_role, ec2_role


def _pick_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, INSTANCE_TYPE)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket. Registered BEFORE the cluster so LIFO empties it AFTER the
    cluster is gone -- EMR keeps writing step logs into LogUri right up to termination."""
    bucket = ctx.unique_name("sim2real-behav-emr-caw-")

    def _cleanup() -> None:
        def _purge_and_delete() -> None:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                           for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if victims:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        _swallow(_purge_and_delete)

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists.

    EMR has no ClusterNotFound code: describing a reaped cluster comes back as
    InvalidRequestException ("Cluster id 'j-...' is not valid"). Throttling, a socket timeout or a
    brief 5xx must NOT be read as termination -- over a wait that can run minutes a transient
    error is likelier than a genuine disappearance, and treating one as "gone" would hand the IAM
    deletions a cluster still assuming the service role.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id, ctx=None):
    """Terminate the cluster and WAIT for the termination to finish.

    TerminateJobFlows returns immediately while EMR spends minutes winding the cluster down, and
    it needs the service role for that whole window. Cleanups run LIFO with the IAM deletions
    registered BEFORE the cluster, so a bare terminate would let delete_role run while EMR is
    still using it -- stranding EC2 instances behind a cluster EMR can no longer tear down, a cost
    leak no assertion here would notice. Bounded: if the wait runs out the teardown raises.
    """
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    deadline = _teardown_deadline(ctx, _CLEANUP_BUDGET_S)
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001
            if _cluster_is_gone(exc):
                return
            time.sleep(2)
            continue
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} did not terminate within the teardown wait")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only the transient IAM-propagation / throttle errors, with teardown
    registered immediately after the id exists."""
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = _run_job_flow_propagated(ctx, emr, ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(
        lambda: _terminate_and_await_teardown(emr, cluster_id, ctx=ctx))
    return cluster_id


def _shell_step(name, script, action="CONTINUE"):
    """A step that runs `script` through bash on the primary node via command-runner.jar.

    command-runner.jar execs its argv directly with no shell, so a redirect or a `&&` only works
    inside an explicit `bash -c`.
    """
    return {"Name": name, "ActionOnFailure": action,
            "HadoopJarStep": {"Jar": "command-runner.jar",
                              "Args": ["bash", "-c", script]}}


def _head_status(s3, bucket, key):
    """HeadObject's error code, or the sentinel 'EXISTS' when the object is really there.

    Never returns a falsy value: an object that exists where the check expects a 404 is the
    strongest signal available, and a falsy sentinel would flatten it into a code mismatch.
    """
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "")
    return "EXISTS"


# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3", "cap:c5")
def run(ctx) -> None:
    """ActionOnFailure=CANCEL_AND_WAIT on a step that really exits non-zero leaves the NEXT step
    CANCELLED with its S3 marker never written, while the preceding control step's marker exists,
    and the cluster stays WAITING."""
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)
    bucket = _make_bucket(ctx, s3)

    nonce1 = ctx.unique_name("caw-marker1-")
    nonce3 = ctx.unique_name("caw-marker3-")
    key1, key3 = "markers/step-1", "markers/step-3"

    def _write_marker(key, nonce):
        return (f"set -e; printf '%s' {nonce} > /tmp/{nonce}; "
                f"aws s3 cp /tmp/{nonce} s3://{bucket}/{key} --region {ctx.region}")

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emr-caw-"),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        # StepConcurrencyLevel=1 is what makes CANCEL_AND_WAIT observable at all: with concurrent
        # steps, step 3 could already be running when step 2 fails.
        StepConcurrencyLevel=1,
        Instances={"InstanceCount": 1, "MasterInstanceType": INSTANCE_TYPE,
                   "KeepJobFlowAliveWhenNoSteps": True, "TerminationProtected": False,
                   "Ec2SubnetId": subnet},
        Applications=[{"Name": "Hadoop"}],
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    def _cluster_state():
        return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]

    waiting = _poll(_cluster_state, lambda s: s not in ("STARTING", "BOOTSTRAPPING"),
                    timeout_s=1000, interval_s=20,
                    description=f"EMR cluster {cluster_id} finishing provisioning")
    assert waiting == "WAITING", (
        f"a keep-alive cluster with no steps must settle in WAITING before the steps are added; "
        f"got {waiting!r} "
        f"({emr.describe_cluster(ClusterId=cluster_id)['Cluster']['Status'].get('StateChangeReason')!r})"
    )

    step_ids = emr.add_job_flow_steps(
        JobFlowId=cluster_id,
        Steps=[
            _shell_step("sim2real-caw-step-1", _write_marker(key1, nonce1)),
            # THE one broken thing: a step that really exits non-zero, asking EMR to cancel what
            # follows and keep the cluster.
            _shell_step("sim2real-caw-step-2", "exit 1", action="CANCEL_AND_WAIT"),
            _shell_step("sim2real-caw-step-3", _write_marker(key3, nonce3)),
        ],
    )["StepIds"]
    assert len(step_ids) == 3, (
        f"AddJobFlowSteps must return one id per submitted step, got {step_ids!r}"
    )
    id1, id2, id3 = step_ids

    def _states():
        listed = {s["Id"]: s["Status"]["State"]
                  for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
                  for s in page.get("Steps", [])}
        return tuple(listed.get(i) for i in (id1, id2, id3))

    final = _poll(_states, lambda st: all(s in _STEP_TERMINAL for s in st),
                  timeout_s=600, interval_s=15,
                  description=f"all three steps on {cluster_id} reaching a terminal state")
    s1, s2, s3_state = final

    # The positive control: this cluster does run steps, and step 1's command really executed.
    assert s1 == "COMPLETED", (
        f"step 1 is the positive control and must reach COMPLETED, got {s1!r} (all three: "
        f"{final!r})"
    )
    body1 = s3.get_object(Bucket=bucket, Key=key1)["Body"].read().decode("utf-8")
    assert body1 == nonce1, (
        f"step 1's command must have written its own nonce to s3://{bucket}/{key1}; expected "
        f"{nonce1!r}, got {body1!r}"
    )

    assert s2 == "FAILED", (
        f"a step whose command exits non-zero must reach FAILED, got {s2!r} (all three: {final!r})"
    )
    assert s3_state == "CANCELLED", (
        f"CANCEL_AND_WAIT on the failed step 2 must leave step 3 CANCELLED -- not FAILED, not "
        f"PENDING -- got {s3_state!r} (all three: {final!r})"
    )

    # The effect-absent half. An emulator that reports CANCELLED while having run the command
    # anyway fails here, and step 1's marker above is what makes this absence meaningful.
    marker3 = _head_status(s3, bucket, key3)
    assert marker3 == "404", (
        f"a CANCELLED step's command must never have executed, so s3://{bucket}/{key3} must not "
        f"exist; HeadObject answered {marker3!r}"
    )

    # ...and WAIT: CANCEL_AND_WAIT must leave the cluster alive, unlike TERMINATE_CLUSTER.
    after = _cluster_state()
    assert after == "WAITING", (
        f"CANCEL_AND_WAIT must leave the cluster WAITING, not terminate it; got {after!r}"
    )


def _run_job_flow_propagated(ctx, emr, **params):
    """RunJobFlow, retrying every 2 s while IAM has not yet propagated a new instance profile to EMR
    ("Failed to authorize instance profile"), to min(180 s, the check's time left); raises the rest."""
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
