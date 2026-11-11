"""security-configuration-sse-kms-applies-to-emrfs-writes."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "security-configuration-sse-kms-applies-to-emrfs-writes"
GROUP = "data-plane"
SERVICES = ["emr"]

# ===== local helpers (self-contained) =====

INSTANCE_TYPE = "m5.xlarge"
# Pinned: emr-6.15.0 uses EMRFS as the s3:// connector. 7.10.0+ defaults to S3A, whose encryption
# knobs are different properties entirely (fs.s3a.encryption.algorithm / .key).
RELEASE_LABEL = "emr-6.15.0"

_SCENARIO = "emr-secconf-sse-kms"
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
# Deliberately the v1 service policy, not AmazonEMRServicePolicy_v2: v2 only grants EMR access to
# network resources tagged for-use-with-amazon-emr-managed-policies.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}


def _swallow(fn):
    """Run fn(), swallowing any exception. TEARDOWN ONLY — never on an assertion path."""
    try:
        fn()
    except Exception:  # noqa: BLE001 — best-effort teardown
        pass


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


def _delete_with_retry(fn, attempts=8, delay=15, ctx=None):
    """Run an IAM delete, retrying DeleteConflict while EMR still holds the instance profile."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown; re-raised on the last attempt
            if "DeleteConflict" not in str(exc) or i == attempts - 1 or _cleanup_spent(ctx):
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx, key_arn):
    """Create the EMR service role and the EC2 instance profile; returns (service, ec2) names.

    S3 calls KMS as the requester for SSE-KMS, so the instance role needs GenerateDataKey on the key.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emrkms-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emrkms-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role), ctx=ctx))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role), ctx=ctx))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    kms_policy = "sim2real-kms-envelope"
    iam.put_role_policy(
        RoleName=ec2_role,
        PolicyName=kms_policy,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
                    "kms:GenerateDataKey*", "kms:DescribeKey",
                ],
                "Resource": key_arn,
            }],
        }),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=ec2_role, PolicyName=kms_policy)
    )

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role), ctx=ctx))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM is eventually consistent; _run_cluster retries the resulting "invalid instanceprofile".
    return svc_role, ec2_role


def _pick_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, INSTANCE_TYPE)[1]


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket, registered BEFORE the cluster so LIFO empties it AFTER."""
    bucket = ctx.unique_name("sim2real-behav-emrkms-")

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

        try:
            _purge_and_delete()
        except Exception as exc:  # noqa: BLE001 — only a bucket that was never made is tolerated
            if "NoSuchBucket" not in str(exc):
                raise

    ctx.on_cleanup(_cleanup)
    # S3's own quirk, not a pin on this check's region: CreateBucket rejects an explicit
    # LocationConstraint of us-east-1 (its API default), so it must be omitted there and
    # supplied for every other region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    return bucket


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists (EMR has no ClusterNotFound)."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id, ctx=None):
    """Terminate and WAIT: EMR needs the service role for the whole wind-down, and cleanups run
    LIFO with the IAM deletions registered first, so a bare terminate strands EC2 instances."""
    _swallow(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False))
    retry_until = _teardown_deadline(ctx, 120)
    while True:
        try:
            emr.terminate_job_flows(JobFlowIds=[cluster_id])
            break
        except Exception as exc:  # noqa: BLE001 — a gone cluster ends it, a throttle is retried
            if _cluster_is_gone(exc):
                return
            low = str(exc).lower()
            if not ("throttl" in low or "rate exceeded" in low) or time.monotonic() >= retry_until:
                raise
            time.sleep(2)
    deadline = _teardown_deadline(ctx, _CLEANUP_BUDGET_S)
    last = None
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(2)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        last = state
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id} did not reach a terminal state by the cleanup deadline after TerminateJobFlows "
        f"(last observed: {last})")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors, registering teardown
    immediately after the id exists."""
    budget = 320.0
    left = ctx.time_left()
    if left is not None:
        budget = min(budget, max(0.0, left))
    deadline = time.monotonic() + budget
    while True:
        try:
            resp = _run_job_flow_propagated(ctx, emr, ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"RunJobFlow still failed with a propagation or throttling error after "
                    f"{budget:.0f} s: {exc}") from exc
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(emr, cluster_id, ctx=ctx))
    return cluster_id


def _new_key(ctx):
    """A symmetric CMK of the check's own; returns its full ARN."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=f"sim2real-behav {_SCENARIO}",
        Tags=[{"TagKey": t["Key"], "TagValue": t["Value"]} for t in _TAGS],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    return key["Arn"]


# ===== end local helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A security configuration's SSE-KMS at-rest mode encrypts EMRFS writes with the named key, while
    a plain S3 API write from the same step takes the bucket's AES256 default and no key id.

    Reference: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html
    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/services-emr.html
    """
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    bucket = _make_bucket(ctx, s3)
    # S3 encrypts every new object by default, so the control needs an explicit, demonstrated
    # AES256 baseline to distinguish it from SSE-KMS.
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    default_rule = s3.get_bucket_encryption(Bucket=bucket)[
        "ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
    assert default_rule["SSEAlgorithm"] == "AES256", (
        f"the control leg needs a demonstrated AES256 bucket default; the bucket reports "
        f"{default_rule!r}"
    )

    key_arn = _new_key(ctx)
    assert key_arn.startswith("arn:") and ":key/" in key_arn, (
        f"CreateKey must report a full KMS key ARN, got {key_arn!r}"
    )

    service_role, job_flow_role = _ensure_emr_roles(ctx, key_arn)
    subnet = _pick_subnet(ctx)

    sec_name = ctx.unique_name("sim2real-behav-emrkms-cfg-")
    emr.create_security_configuration(
        Name=sec_name,
        SecurityConfiguration=json.dumps({
            "EncryptionConfiguration": {
                "EnableInTransitEncryption": False,
                "EnableAtRestEncryption": True,
                "AtRestEncryptionConfiguration": {
                    "S3EncryptionConfiguration": {
                        "EncryptionMode": "SSE-KMS",
                        "AwsKmsKey": key_arn,
                    }
                },
            }
        }),
    )
    ctx.on_cleanup(lambda: emr.delete_security_configuration(Name=sec_name))

    # A run-unique payload, so the object cannot be a leftover from any earlier run and the bytes
    # asserted are ones this run minted.
    nonce = ctx.unique_name("sse-kms-payload-")
    emrfs_key = f"emrfs/{nonce}"
    direct_key = f"direct/{nonce}"
    # Both writes are the same bytes from the same local file in the same step. `hadoop fs -put`
    # goes through EMRFS; `aws s3 cp` goes through the plain S3 API. That difference is the only
    # difference between the two objects.
    #
    # A failed command-runner step reports an empty StateChangeReason, and the log agent pushes
    # only every 5 minutes, so the step uploads its own transcript for diagnosis.
    debug_key = f"debug/{nonce}.log"
    script = (
        f"set -u; printf '%s' '{nonce}' > /tmp/{nonce}; "
        f"{{ echo '=== aws s3 ls (ListBucket probe) ==='; "
        f"aws s3 ls s3://{bucket}/ --region {ctx.region} 2>&1; echo EXIT_LIST=$?; "
        f"echo '=== hadoop fs -ls s3://bucket/ ==='; "
        f"hadoop fs -ls s3://{bucket}/ 2>&1; echo EXIT_HLIST=$?; "
        f"echo '=== hadoop fs -mkdir -p (parent probe) ==='; "
        f"hadoop fs -mkdir -p s3://{bucket}/emrfs/ 2>&1; echo EXIT_MKDIR=$?; "
        f"echo '=== hadoop fs -put ==='; "
        f"hadoop fs -put /tmp/{nonce} s3://{bucket}/{emrfs_key} 2>&1; echo EXIT_EMRFS=$?; "
        f"echo '=== aws s3 cp ==='; "
        f"aws s3 cp /tmp/{nonce} s3://{bucket}/{direct_key} --region {ctx.region} 2>&1; "
        f"echo EXIT_DIRECT=$?; }} > /tmp/{nonce}.log 2>&1; "
        f"aws s3 cp /tmp/{nonce}.log s3://{bucket}/{debug_key} --region {ctx.region} || true; "
        f"grep -q EXIT_EMRFS=0 /tmp/{nonce}.log && grep -q EXIT_DIRECT=0 /tmp/{nonce}.log"
    )
    step = {
        "Name": "sim2real-behav-emrkms-write",
        "ActionOnFailure": "CONTINUE",
        "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", script]},
    }

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emrkms-"),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Applications=[{"Name": "Hadoop"}],
        Instances={
            "InstanceGroups": [{
                "Name": "sim2real-primary", "InstanceRole": "MASTER",
                "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND",
            }],
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
            "Ec2SubnetId": subnet,
        },
        Steps=[step],
        SecurityConfiguration=sec_name,
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    # The cluster must actually be carrying the configuration, or the encryption assertions below
    # would be measuring nothing in particular.
    launched = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    assert launched.get("SecurityConfiguration") == sec_name, (
        f"the cluster must report the security configuration it was launched with "
        f"({sec_name!r}), got {launched.get('SecurityConfiguration')!r}"
    )

    step_id = emr.list_steps(ClusterId=cluster_id)["Steps"][0]["Id"]
    final = _poll(
        lambda: emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"],
        lambda s: s["Status"]["State"] in TERMINAL_STEP_STATES,
        timeout_s=1500,  # cluster provisioning takes 5-10 minutes before the step runs
        interval_s=20,
        description=f"the EMRFS write step on {cluster_id} reaches a terminal state",
    )
    transcript = ""
    if final["Status"]["State"] != "COMPLETED":
        try:
            transcript = s3.get_object(Bucket=bucket, Key=debug_key)["Body"].read().decode(
                "utf-8", "replace"
            )
        except Exception as exc:  # noqa: BLE001 — best-effort diagnostic, not the assertion itself
            transcript = f"<debug log unavailable: {exc!r}>"
    assert final["Status"]["State"] == "COMPLETED", (
        f"the EMRFS write step must COMPLETE; got {final['Status']['State']!r} "
        f"(StateChangeReason: {final['Status'].get('StateChangeReason')!r}). A step that cannot "
        f"write to s3://{bucket} cannot demonstrate anything about how the write was encrypted. "
        f"Step transcript from s3://{bucket}/{debug_key}:\n{transcript}"
    )

    # --- THE assertion: independent reads at S3, through operations EMR never touched.
    emrfs_head = s3.head_object(Bucket=bucket, Key=emrfs_key)
    assert emrfs_head["ServerSideEncryption"] == "aws:kms", (
        f"an EMRFS write under a security configuration with EncryptionMode=SSE-KMS must land "
        f"SSE-KMS encrypted; s3://{bucket}/{emrfs_key} reports ServerSideEncryption="
        f"{emrfs_head.get('ServerSideEncryption')!r}"
    )
    assert emrfs_head["SSEKMSKeyId"] == key_arn, (
        f"the EMRFS object must be encrypted under the AwsKmsKey the security configuration named; "
        f"expected {key_arn!r}, S3 reports {emrfs_head.get('SSEKMSKeyId')!r}"
    )

    # --- the twin control, same node and same step: plain S3 API, so the bucket default only.
    direct_head = s3.head_object(Bucket=bucket, Key=direct_key)
    assert direct_head["ServerSideEncryption"] == "AES256", (
        f"the control write (plain S3 API from the same node in the same step) must take the "
        f"bucket's AES256 default, not SSE-KMS — otherwise the SSE-KMS above proves nothing about "
        f"EMRFS. s3://{bucket}/{direct_key} reports "
        f"{direct_head.get('ServerSideEncryption')!r}/{direct_head.get('SSEKMSKeyId')!r}"
    )
    assert "SSEKMSKeyId" not in direct_head, (
        f"the control write must carry no KMS key id; got {direct_head.get('SSEKMSKeyId')!r} for "
        f"s3://{bucket}/{direct_key}"
    )

    # The encryption must be transparent, not lossy: the bytes have to come back intact, which
    # means the envelope really was decryptable with the same key.
    body = s3.get_object(Bucket=bucket, Key=emrfs_key)["Body"].read()
    assert body == nonce.encode("utf-8"), (
        f"the SSE-KMS encrypted EMRFS object must decrypt to exactly the bytes the step wrote; "
        f"expected {nonce!r}, read back {body!r}"
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
