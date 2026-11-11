"""emrfs-write-through-hadoop-fs-is-read-by-the-next-step."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "emrfs-write-through-hadoop-fs-is-read-by-the-next-step"
GROUP = "data-plane"
SERVICES = ["emr"]

_SCENARIO = "emr-emrfs-write-path"
_PREFIX = "sim2real-behav-emrfw-"

# Quoted verbatim from the EMRFS-to-S3A migration guide, which names it as the value to put in
# core-site.xml to keep EMRFS on emr-7.10.0+ — i.e. the default on every earlier release line,
# including the emr-6.15.0 this check pins.
_EMRFS_IMPL = "com.amazon.ws.emr.hadoop.fs.EmrFileSystem"
_OBJECT_KEY = "emrfs/payload.txt"
_ABSENT_KEY = "emrfs/never-written.txt"

# ===== helpers =====
# `_pick_subnet` creates and owns its own VPC/subnet/IGW/route rather than reading the account's
# default VPC: a freshly provisioned account need not have one.

INSTANCE_TYPE = "m5.xlarge"
# Pinned to the 6.x line ON PURPOSE. From emr-7.10.0 the S3A filesystem replaces EMRFS as the
# default s3:// connector for every scheme
# (https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-s3a-migrate.html), which changes what
# `fs.s3.impl` resolves to and which committer writes. The other EMR checks pin this same label.
RELEASE_LABEL = "emr-6.15.0"

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
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
# The legacy service policy deliberately, NOT AmazonEMRServicePolicy_v2: v2 only grants EMR access
# to network resources carrying the `for-use-with-amazon-emr-managed-policies` tag, which would make
# the check depend on the account's default VPC being pre-tagged.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
# Grants the cluster's EC2 instances the S3 (and Glue catalog) access that makes the data plane
# below reachable at all.
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
BAD_CLUSTER_STATES = {"TERMINATED_WITH_ERRORS", "INTERNAL_ERROR"}

# Written by a step when a read it was told to attempt found nothing. A literal the check controls,
# so "the read really happened and really came back empty" is an observable value rather than a
# swallowed error.
_MISSING = "MISSING"


def _ignore_not_found(fn):
    """Run a teardown call: a resource that is already gone is fine, any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket", "InvalidGroup.NotFound", "InvalidPermission.NotFound"
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


def _delete_with_retry(ctx, run_state: dict, fn):
    """Run an IAM delete: NoSuchEntity is done; DeleteConflict (EMR still holds the instance
    profile) is retried every 2 s to the run's cleanup deadline; anything else raises."""
    deadline = _cleanup_deadline(ctx, run_state)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                return
            if code != "DeleteConflict" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _ensure_emr_roles(ctx, run_state: dict):
    """Create the EMR service role and the EC2 instance profile; returns (service, ec2) names.

    Created in-check: EMR_DefaultRole / EMR_EC2_DefaultRole do NOT exist in a fresh account, so
    naming them would surface as an untagged ClientError instead of as EMR behaviour.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name(_PREFIX + "svc-")
    ec2_role = ctx.unique_name(_PREFIX + "ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(ctx, run_state, lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(ctx, run_state, lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(ctx, run_state,
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM eventual consistency: poll IAM's own read path for the instance profile it just
    # created, bounded with a deadline, rather than an unconditional sleep. No assertion depends
    # on it: RunJobFlow's own transient retry in _run_cluster is the backstop if propagation
    # outlasts this floor.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=ec2_role)
            break
        except Exception:  # noqa: BLE001 — prerequisite polling only, never an assertion
            time.sleep(2)
    return svc_role, ec2_role


def _pick_subnet(ctx, run_state: dict):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, run_state, INSTANCE_TYPE)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket, registered BEFORE the cluster so LIFO empties it AFTER."""
    bucket = ctx.unique_name(_PREFIX)

    def _cleanup():
        def _purge_and_delete():
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                           for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if victims:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        _ignore_not_found(_purge_and_delete)

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists.

    EMR has no ClusterNotFound code: describing a reaped cluster comes back as
    InvalidRequestException ("Cluster id 'j-...' is not valid"). Throttling, a socket timeout or a
    brief 5xx must NOT be read as termination — over a long wait a transient is far likelier than a
    genuine disappearance, and treating one as "gone" hands the IAM deletions a cluster that is
    still assuming the service role.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(ctx, run_state: dict, emr, cluster_id):
    """Terminate and WAIT: EMR needs the service role for the whole wind-down, and cleanups run
    LIFO with the IAM deletions registered first, so a bare terminate strands the EC2 fleet."""
    try:
        emr.set_termination_protection(JobFlowIds=[cluster_id], TerminationProtected=False)
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
    except ClientError as exc:
        if _cluster_is_gone(exc):
            return
        # A cluster already shutting down refuses the modify; await its termination below.
        if "may not be modified" not in exc.response["Error"].get("Message", ""):
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
            if state not in TERMINAL_CLUSTER_STATES:
                raise
            return
    deadline = _cleanup_deadline(ctx, run_state)
    while True:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            if _cluster_is_gone(exc):
                return
            raise
        if state in TERMINAL_CLUSTER_STATES:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"EMR cluster {cluster_id} did not terminate by the run's cleanup deadline (last {state})")
        time.sleep(2)


def _run_cluster(emr, ctx, run_state: dict, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors, registering the
    terminate-and-wait teardown immediately after the id exists."""
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low
                         or "failed to authorize instance profile" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, run_state, emr, cluster_id))
    return cluster_id


def _instances(subnet, keep_alive=True, core=0):
    """One primary, optionally `core` core nodes. KeepJobFlowAliveWhenNoSteps=True by default so
    the only thing that can end the cluster is the teardown: an ALL_STEPS_COMPLETED auto-shutdown
    would race the S3 reads the assertions depend on."""
    groups = [{
        "Name": "sim2real-primary", "InstanceRole": "MASTER",
        "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND",
    }]
    if core:
        groups.append({
            "Name": "sim2real-core", "InstanceRole": "CORE",
            "InstanceType": INSTANCE_TYPE, "InstanceCount": core, "Market": "ON_DEMAND",
        })
    return {
        "InstanceGroups": groups,
        "KeepJobFlowAliveWhenNoSteps": keep_alive,
        "TerminationProtected": False,
        "Ec2SubnetId": subnet,
    }


def _shell_step(name, script, on_failure="CONTINUE"):
    """A step that runs `script` through the cluster's own shell via command-runner.jar."""
    return {
        "Name": name,
        "ActionOnFailure": on_failure,
        "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", script]},
    }


def _await_step(emr, cluster_id, step_id, *, timeout_s, description):
    """Wait for one step to reach a TERMINAL state and return the described step."""
    return _poll(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=timeout_s,
        interval_s=20,
        description=description,
    )


def _steps_by_name(emr, cluster_id):
    """Every step on the cluster, keyed by Name. Hard-subscripted by the caller."""
    return {
        s["Name"]: s
        for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
        for s in page["Steps"]
    }


def _get_text(s3, bucket, key):
    """Read an object as text. No try/except: a missing key must fail loudly, not degrade."""
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8").strip()


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix. `.get("Contents", [])` is correct here: it feeds exact set/count
    equalities and absence assertions."""
    return sorted(
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    )


# ===== end helpers =====

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An object written through EMRFS (`hadoop fs -put`, not the AWS CLI) is byte-identical via the
    S3 API, readable in the same step and by the next step, and `fs.s3.impl` resolves to EMRFS; a
    never-written key reads back empty, so the positive reads are not vacuous.
    """
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS must report the account id before any cluster is launched"

    bucket = _make_bucket(ctx, s3)
    service_role, job_flow_role = _ensure_emr_roles(ctx, run_state)
    subnet = _pick_subnet(ctx, run_state)

    payload = ctx.unique_name("emrfs-payload-")
    region = ctx.region

    # Step 1: report what fs.s3.impl resolves to, write through EMRFS, and read it straight back
    # through EMRFS with no sleep. The reports go out through the AWS CLI so the EMRFS leg and the
    # transport that carries its verdict are different mechanisms. EMRFS requires the parent prefix
    # to exist as a directory before `hadoop fs -put` (a raw PutObject does not), hence the mkdir.
    write_script = (
        f"set -eu; "
        f"hdfs getconf -confKey fs.s3.impl > /tmp/impl; "
        f"printf %s '{payload}' > /tmp/payload; "
        f"hadoop fs -mkdir -p s3://{bucket}/emrfs; "
        f"hadoop fs -put /tmp/payload s3://{bucket}/{_OBJECT_KEY}; "
        f"hadoop fs -cat s3://{bucket}/{_OBJECT_KEY} > /tmp/read_after_write; "
        f"hadoop fs -du -s s3://{bucket}/{_OBJECT_KEY} | awk '{{print $1}}' > /tmp/bytes; "
        f"aws s3 cp /tmp/impl s3://{bucket}/step1/impl.txt --region {region}; "
        f"aws s3 cp /tmp/read_after_write s3://{bucket}/step1/read_after_write.txt "
        f"--region {region}; "
        f"aws s3 cp /tmp/bytes s3://{bucket}/step1/bytes.txt --region {region}"
    )

    # Step 2: read the same object through EMRFS on the other side of a step boundary, plus the
    # never-written control. `set -u` only — the control read is expected to fail.
    read_script = (
        f"set -u; "
        f"hadoop fs -cat s3://{bucket}/{_OBJECT_KEY} > /tmp/observed; "
        f"(hadoop fs -cat s3://{bucket}/{_ABSENT_KEY} > /tmp/control 2>/dev/null) "
        f"|| printf '{_MISSING}' > /tmp/control; "
        f"aws s3 cp /tmp/observed s3://{bucket}/step2/observed.txt --region {region}; "
        f"aws s3 cp /tmp/control s3://{bucket}/step2/control.txt --region {region}"
    )

    write_name = "sim2real-emrfs-write"
    read_name = "sim2real-emrfs-read"

    cluster_id = _run_cluster(
        emr, ctx, run_state, service_role, job_flow_role,
        Name=ctx.unique_name(_PREFIX),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}],
        Instances=_instances(subnet, keep_alive=True, core=1),
        StepConcurrencyLevel=1,
        Steps=[
            _shell_step(write_name, write_script),
            _shell_step(read_name, read_script),
        ],
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    submitted = _steps_by_name(emr, cluster_id)
    assert set(submitted) == {write_name, read_name}, (
        f"ListSteps must report exactly the two submitted steps, got {sorted(submitted)!r}"
    )
    write_id, read_id = submitted[write_name]["Id"], submitted[read_name]["Id"]

    read_step = _await_step(
        emr, cluster_id, read_id, timeout_s=1800,
        description=f"the EMRFS-read step {read_id} on {cluster_id} reaches a terminal state",
    )
    write_step = emr.describe_step(ClusterId=cluster_id, StepId=write_id)["Step"]

    assert write_step["Status"]["State"] == "COMPLETED", (
        f"the EMRFS WRITE step must COMPLETE — `set -eu` means a FAILED step here is a failed "
        f"`hadoop fs -put` or a failed same-step read-back. Got {write_step['Status']['State']!r} "
        f"(reason {write_step['Status'].get('StateChangeReason')!r}, "
        f"failure {write_step['Status'].get('FailureDetails')!r})"
    )
    assert read_step["Status"]["State"] == "COMPLETED", (
        f"the EMRFS READ step must COMPLETE; got {read_step['Status']['State']!r} "
        f"(reason {read_step['Status'].get('StateChangeReason')!r}, "
        f"failure {read_step['Status'].get('FailureDetails')!r})"
    )

    w_end = write_step["Status"]["Timeline"].get("EndDateTime")
    r_start = read_step["Status"]["Timeline"].get("StartDateTime")
    assert w_end is not None and r_start is not None, (
        f"both steps must carry an execution window; write EndDateTime={w_end!r}, "
        f"read StartDateTime={r_start!r}"
    )
    assert r_start >= w_end, (
        f"at StepConcurrencyLevel=1 the read step cannot start ({r_start}) before the write step "
        f"ended ({w_end})"
    )

    # --- the write really went through EMRFS, not through some other S3 client.
    impl = _get_text(s3, bucket, "step1/impl.txt")
    assert impl == _EMRFS_IMPL, (
        f"on {RELEASE_LABEL} the cluster's fs.s3.impl must resolve to EMRFS: expected "
        f"{_EMRFS_IMPL!r}, the cluster reported {impl!r} (the S3A class here would mean this "
        f"release line has already migrated and the check needs re-cutting)"
    )

    # --- read-after-write through EMRFS, in the same step, with no sleep: the documented contract.
    same_step = _get_text(s3, bucket, "step1/read_after_write.txt")
    assert same_step == payload, (
        f"EMRFS must serve back exactly what it just wrote, on the first read and with no retry: "
        f"expected {payload!r}, got {same_step!r}"
    )

    # --- THE assertion: the AWS S3 API serves the same bytes the Hadoop FileSystem wrote.
    body = s3.get_object(Bucket=bucket, Key=_OBJECT_KEY)["Body"].read().decode("utf-8")
    assert body == payload, (
        f"the object `hadoop fs -put` wrote must be byte-identical through the AWS S3 API: "
        f"expected {payload!r} at s3://{bucket}/{_OBJECT_KEY}, got {body!r}"
    )

    # --- and the length agrees three ways, so a fabricated `hadoop fs` transcript cannot pass.
    api_length = s3.head_object(Bucket=bucket, Key=_OBJECT_KEY)["ContentLength"]
    emrfs_length = _get_text(s3, bucket, "step1/bytes.txt")
    assert emrfs_length.isdigit(), (
        f"`hadoop fs -du -s` must report an integer byte count, got {emrfs_length!r}"
    )
    assert int(emrfs_length) == api_length == len(payload.encode("utf-8")), (
        f"EMRFS, the S3 API and the payload must agree on the object length: EMRFS said "
        f"{emrfs_length}, HeadObject said {api_length}, the payload is "
        f"{len(payload.encode('utf-8'))} bytes"
    )

    # --- the cross-step read, and the never-written control that makes it mean something.
    observed = _get_text(s3, bucket, "step2/observed.txt")
    assert observed == payload, (
        f"step 2 must read the same object back through EMRFS: expected {payload!r} at "
        f"s3://{bucket}/step2/observed.txt, got {observed!r}"
    )
    control = _get_text(s3, bucket, "step2/control.txt")
    assert control == _MISSING, (
        f"reading s3://{bucket}/{_ABSENT_KEY} through EMRFS must report {_MISSING!r} — if it also "
        f"returned the payload, the reads above prove nothing. Got {control!r}"
    )

    # --- the write left exactly one object under the data prefix: no staging or placeholder debris.
    data_keys = _keys_under(s3, bucket, "emrfs/")
    assert data_keys == [_OBJECT_KEY], (
        f"the EMRFS write must leave exactly the one object it was asked for; got {data_keys!r}"
    )


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route, and a gateway
#: endpoint to S3 (all EMR needs there) is the only way out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's 900 s cleanup budget less a margin: one deadline per run, started by the first
#: teardown that asks for it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 840.0
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
})


def _private_network(ctx, run_state: dict, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type; its teardown is registered before any cluster is placed in it."""
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
    tags = [{"Key": "sim2real:managed", "Value": "true"}]
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
    run_state["network"] = (vpc_id, subnet_id)
    return vpc_id, subnet_id


def _cleanup_deadline(ctx, run_state: dict) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    return run_state.setdefault("deadline", time.monotonic() + _CLEANUP_BUDGET_S)


def _track_cluster(ctx, run_state: dict, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        run_state.setdefault("clusters", set()).add(cluster_id)


def _drop_private_network(ctx, run_state: dict, vpc_id: str) -> None:
    """Delete the check's VPC: wait for its EMR clusters to terminate, delete its endpoints, wait for
    its interfaces to release, clear then delete every non-default group (EMR's reference each other),
    route tables, subnets, the VPC. Retries in-use refusals every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    run_state.pop("network", None)
    created = run_state.pop("clusters", set())
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
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
