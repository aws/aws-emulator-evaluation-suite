"""emr-step-args-are-passed-verbatim-to-the-application."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "emr-step-args-are-passed-verbatim-to-the-application"
GROUP = 'data-plane'
SERVICES = ['emr']

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

_SCENARIO = "emr-step-argv"
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
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_STEP_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED",
                  "TERMINATED_WITH_ERRORS", "INTERNAL_ERROR"}
_CLUSTER_GONE_CODES = ("InvalidRequestException", "ClusterNotFound",
                       "ResourceNotFoundException", "EntityNotFoundException")

# The application under test. It reports the RAW BYTES of each argument it received, base64'd, so
# the comparison is byte-exact and immune to the node's locale: os.fsencode reverses exactly the
# decoding CPython applied to argv, and base64 then survives any redirect or transfer untouched.
# Comparing decoded strings instead would let a locale difference on the node masquerade as an EMR
# argv defect (or hide one).
_DUMPER = '''import base64
import json
import os
import sys

argv = [base64.b64encode(os.fsencode(a)).decode("ascii") for a in sys.argv[1:]]
sys.stdout.write(json.dumps(argv))
'''

# The awkward argument list. Each element probes a distinct way a backend can mangle argv:
# an argument containing spaces (re-splitting), embedded double and single quotes (re-quoting),
# the EMPTY STRING (silently dropped), a shell metacharacter and a glob (expansion), a
# dollar-sign (variable expansion), and a non-ASCII character (transcoding).
_AWKWARD = [
    "plain",
    "two words",
    'has"double"quote',
    "has'single'quote",
    "",
    "semi;colon&amp",
    "star*glob?",
    "$NOT_EXPANDED",
    "ünïcodé-λ-é",
    "trailing space ",
]

# What the process actually receives on AWS. Every
# awkward argument survives byte-identically -- spaces, both kinds of quote, `;`, `&`, glob
# metacharacters, a dollar sign, a multi-byte character and a trailing space -- with exactly one
# exception: the ZERO-LENGTH argument is dropped. DescribeStep's Config.Args still records it (the
# echo assertion below passes), so EMR's control plane and its command-runner genuinely disagree
# about that one element, and this check asserts each end separately. Its position is observable: the observed list runs straight from the element before it to the
# element after it, so it is dropped rather than transformed.
_DELIVERED = [a for a in _AWKWARD if a != ""]


def _ignore_not_found(fn):
    """Run a teardown call: a resource that is already gone is fine, any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket", "InvalidGroup.NotFound", "InvalidPermission.NotFound"
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

    EMR_DefaultRole and EMR_EC2_DefaultRole do NOT exist in a fresh account, so
    pointing at them would surface as an untagged ClientError rather than as EMR behaviour.
    Cleanups registered immediately after each create, so LIFO yields the only order IAM accepts.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-argv-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-argv-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role), ctx=ctx))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role), ctx=ctx))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role), ctx=ctx))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # No blind wait for IAM propagation here: _run_cluster retries RunJobFlow on "invalid
    # instanceprofile" / "invalid ec2" until IAM catches up, to a deadline.
    return svc_role, ec2_role


def _pick_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, INSTANCE_TYPE)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket. Registered BEFORE the cluster so LIFO empties it AFTER the
    cluster is gone -- EMR keeps writing step logs into LogUri right up to termination."""
    bucket = ctx.unique_name("sim2real-behav-emr-argv-")

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

        _ignore_not_found(_purge_and_delete)

    ctx.on_cleanup(_cleanup)
    # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1 itself; this follows
    # ctx.region, it does not pin the bucket to a fixed region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists.

    EMR has no ClusterNotFound code: describing a reaped cluster comes back as
    InvalidRequestException. Throttling or a brief 5xx must NOT be read as termination, or the IAM
    deletions would run against a cluster still assuming the service role.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id, ctx=None):
    """Terminate the cluster and WAIT for the termination to finish.

    TerminateJobFlows returns immediately while EMR spends minutes winding the cluster down, and it
    needs the service role for that whole window. Cleanups run LIFO with the IAM deletions
    registered BEFORE the cluster, so a bare terminate would let delete_role run while EMR is
    still using it -- stranding EC2 instances behind a cluster EMR can no longer tear down.
    """
    try:
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
    except ClientError as exc:
        if _cluster_is_gone(exc):
            return
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state not in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise
        return
    deadline = _teardown_deadline(ctx, _CLEANUP_BUDGET_S)
    while True:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            if _cluster_is_gone(exc):
                return
            raise
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"EMR cluster {cluster_id} did not terminate by the cleanup deadline (last {state})")
        time.sleep(2)


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


# ===== end helpers =====


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
    "cap:c5",
)
def run(ctx) -> None:
    """DescribeStep echoes a step's Args verbatim, including the empty string, while the program on
    the cluster receives them as a byte-identical argv minus only the zero-length argument; the
    two ends are asserted separately because they genuinely disagree on that one element.
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)
    bucket = _make_bucket(ctx, s3)

    dumper_key, out_key = "app/dump_argv.py", "out/argv.json"
    s3.put_object(Bucket=bucket, Key=dumper_key, Body=_DUMPER.encode("utf-8"), Tagging="sim2real=" + _SCENARIO)

    # `bash -c SCRIPT NAME a b c` binds NAME to $0 and a/b/c to $1.., and `"$@"` re-expands them
    # as separate words without re-splitting or globbing -- so whatever EMR handed bash is exactly
    # what python3 receives. The awkward list is therefore delivered, not interpreted.
    script = (
        f"set -eu; "
        f"aws s3 cp s3://{bucket}/{dumper_key} /tmp/dump_argv.py --region {ctx.region}; "
        f"python3 /tmp/dump_argv.py \"$@\" > /tmp/argv.json; "
        f"aws s3 cp /tmp/argv.json s3://{bucket}/{out_key} --region {ctx.region}"
    )
    submitted_args = ["bash", "-c", script, "sim2real-argv-probe"] + _AWKWARD

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emr-argv-"),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Instances={"InstanceCount": 1, "MasterInstanceType": INSTANCE_TYPE,
                   "KeepJobFlowAliveWhenNoSteps": True, "TerminationProtected": False,
                   "Ec2SubnetId": subnet},
        Applications=[{"Name": "Hadoop"}],
        VisibleToAllUsers=True,
        Tags=_TAGS,
        Steps=[{"Name": "sim2real-argv-echo", "ActionOnFailure": "CONTINUE",
                "HadoopJarStep": {"Jar": "command-runner.jar", "Args": submitted_args}}],
    )

    step_ids = [s["Id"]
                for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id)
                for s in page.get("Steps", [])]
    assert len(step_ids) == 1, (
        f"the cluster must hold exactly the one step submitted at launch, got {step_ids!r}"
    )
    step_id = step_ids[0]

    # Half one: the control-plane record. DescribeStep must echo the argv it was given, including
    # the empty string, before the step has run at all.
    echoed = emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]["Config"]["Args"]
    assert list(echoed) == submitted_args, (
        f"DescribeStep must echo the submitted Args verbatim.\n  submitted: {submitted_args!r}\n"
        f"  echoed:    {list(echoed)!r}"
    )

    final = _poll(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]["Status"]["State"],
        lambda s: s in _STEP_TERMINAL,
        timeout_s=1400, interval_s=20,
        description=f"argv step {step_id} on cluster {cluster_id} reaching a terminal state")
    assert final == "COMPLETED", (
        f"the argv-reporting step must reach COMPLETED, got {final!r} "
        f"({emr.describe_step(ClusterId=cluster_id, StepId=step_id)['Step']['Status'].get('FailureDetails')!r})"
    )

    # Half two: the delivery. The program's own report of its argv, byte for byte.
    raw = _poll(lambda: _get_or_none(s3, bucket, out_key), lambda b: b is not None,
                timeout_s=120, interval_s=5,
                description=f"the step's argv report at s3://{bucket}/{out_key}")
    reported_b64 = json.loads(raw.decode("utf-8"))
    reported = [base64.b64decode(b) for b in reported_b64]
    expected = [a.encode("utf-8") for a in _DELIVERED]
    assert reported == expected, (
        f"the program on the cluster must observe the submitted Args as a byte-identical argv "
        f"list, in order, with only the zero-length argument absent.\n"
        f"  submitted: {[a.encode('utf-8') for a in _AWKWARD]!r}\n"
        f"  expected:  {expected!r}\n  observed:  {reported!r}"
    )
    # Asserted separately, because it is the one place where the two ends legitimately DISAGREE and
    # an equality above would not say which end an emulator got wrong: the control-plane record
    # keeps the zero-length argument (the DescribeStep assertion above passes) while the
    # command-runner does not hand it to the process.
    assert b"" not in reported, (
        f"EMR's command-runner does not deliver a zero-length argument to the process, so no empty "
        f"element may appear in the observed argv; got {reported!r}"
    )
    assert len(reported) == len(_AWKWARD) - 1, (
        f"exactly one argument -- the zero-length one -- is dropped in delivery: {len(_AWKWARD)} "
        f"submitted, {len(_DELIVERED)} expected, {len(reported)} observed ({reported!r})"
    )


def _get_or_none(s3, bucket, key):
    """The object's bytes, or None while it is not there yet. Teardown-free read helper."""
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception:  # noqa: BLE001 — absence is the polled condition
        return None


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
