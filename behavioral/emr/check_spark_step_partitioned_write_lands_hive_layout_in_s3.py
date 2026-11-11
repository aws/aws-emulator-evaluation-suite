"""spark-step-partitioned-write-lands-hive-layout-in-s3."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "spark-step-partitioned-write-lands-hive-layout-in-s3"
GROUP = "data-plane"
SERVICES = ["emr"]

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

# The network this check builds for itself. Two VPCs in one account may carry the same CIDR (they
# are not peered and nothing routes between them), so a literal here cannot collide with a sibling
# run's VPC the way a shared *resource* would.
_VPC_CIDR = "10.83.0.0/16"
_SUBNET_CIDR = "10.83.1.0/24"

# One overall budget, because the phases are strictly sequential and their SUM is what the wrapper
# has to cover. The per-check timeout this is sized against is 1800 s;
# this stays under it with margin so the check runs its own verified teardown rather than being
# killed mid-way (a check SIGKILLed at the ceiling strands the cluster: the cleanup chain is joined
# on a 60 s daemon thread and never affects the verdict).
# The body's phases share one clock (_TOTAL_BUDGET_S); the two teardowns then take their own
# floors on top of it, so the worst case is 1450 + 120 + 180 = 1750 s and still clears the wrapper.
_TOTAL_BUDGET_S = 1450.0
_STEP_BUDGET_S = 900.0
_OUTPUT_BUDGET_S = 180.0
_TEARDOWN_BUDGET_S = 330.0
_TEARDOWN_FLOOR_S = 120.0
_NETWORK_TEARDOWN_BUDGET_S = 300.0
_NETWORK_TEARDOWN_FLOOR_S = 180.0

# ===== helpers =====
# The check builds its own network: reading the account's default VPC would make it fail on a
# freshly provisioned account and grade the account rather than EMR. `_create_network`/`_delete_network`
# below build and destroy their own.

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
# this check depend on the account's network being pre-tagged.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}

# The input this check writes to S3 and then makes Spark aggregate. The expected output is derived
# from these rows in Python below, never written as a literal.
_ROWS = (("eng", 7), ("ops", 11), ("eng", 5), ("ops", 4), ("eng", 2))

# A real PySpark job: read the CSV the check uploaded, aggregate it, and write the result
# partitioned by `dept`. `repartition(1)` makes the number of part files per partition directory
# deterministic (one), which is what lets the layout below be asserted exactly rather than counted.
_SPARK_JOB = '''\
import sys

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, first
from pyspark.sql.functions import sum as sum_

src, out = sys.argv[1:3]
spark = SparkSession.builder.appName("sim2real-emr-partitioned-write").getOrCreate()
rows = spark.read.option("header", "true").csv(src)
agg = (
    rows.withColumn("amount", col("amount").cast("long"))
    .groupBy("dept")
    .agg(sum_("amount").alias("total"), first("run").alias("run"))
)
agg.repartition(1).write.mode("overwrite").partitionBy("dept").json(out)
spark.stop()
'''


class _Deadline:
    """A single wall-clock budget shared by every phase, so their sum cannot exceed the wrapper."""

    def __init__(self, total_s: float) -> None:
        self.end = time.monotonic() + total_s

    def left(self, cap_s: float) -> float:
        return max(0.0, min(cap_s, self.end - time.monotonic()))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_with_retry(fn, attempts: int = 6, delay: float = 10.0) -> None:
    """Run an IAM delete, retrying DeleteConflict.

    Even once the cluster reports TERMINATED, IAM can briefly still see the instance profile as in
    use; without the retry the only symptom of losing that race is a leaked role nobody looks at.
    """
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx, iam) -> tuple[str, str]:
    """Create the EMR service role and the EC2 instance profile, both deleted on teardown.

    The check builds these prerequisites itself rather than reading them from the environment.
    """
    svc_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name.
    iam.create_instance_profile(InstanceProfileName=ec2_role)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM exposes no condition to poll for "EMR can see this profile", so there is nothing to wait
    # on here. The RunJobFlow retry loop below is the actual bounded wait: it retries specifically
    # on "invalid instanceprofile"/"invalid ec2", which is what makes this correct regardless of how
    # long IAM's propagation to EMR takes.
    return svc_role, ec2_role


def _net_tags(ctx, kind: str) -> list[dict]:
    """Tags for an EC2 resource, applied in the SAME call that creates it.

    Not a follow-up `create_tags`: tag at creation so an aborted run's resources can still be found
    by their sim2real tag; any abort between the create and a follow-up tag call is exactly how a
    leak becomes unattributable.
    """
    return [{
        "ResourceType": kind,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-emr-{kind}-")},
                 {"Key": "sim2real", "Value": CHECK}],
    }]


def _already_gone(exc) -> bool:
    """True only for "what you are deleting does not exist", which is what makes teardown idempotent.

    Deliberately narrow, and it must stay that way: a `DependencyViolation` (the cluster's ENIs have
    not drained yet) must NOT read as gone, or the retry loop below stops while the resources are
    still live.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code.endswith(".NotFound") or code == "Gateway.NotAttached"


def _swallow_gone(fn, errors: list[str], label: str) -> None:
    """Attempt one delete; note it in *errors* while a dependency still holds the resource.

    Already-gone counts as done; any other error raises, so a teardown failure is never swallowed.
    """
    try:
        fn()
    except ClientError as exc:
        if _already_gone(exc):
            return
        if exc.response["Error"]["Code"] != "DependencyViolation":
            raise
        errors.append(f"{label}: {exc}")


def _best_effort(fn) -> None:
    """A per-resource failure-path net. The authoritative teardown is `_delete_network`, which is
    called inline and whose result is asserted; this only covers the paths that never reach it."""
    _swallow_gone(fn, [], "")


def _create_network(ctx, ec2) -> tuple[str, str]:
    """Build the VPC, public subnet, gateway and default route this cluster runs in.

    The account's DEFAULT VPC is deliberately NOT used. A freshly provisioned account need not have
    one, so a check that reads the ambient network grades this account
    rather than EMR: it FAILS on a clean account for a reason that says nothing about the service.

    The AZ is DERIVED — never omitted, never a literal. `create_subnet` with no `AvailabilityZone`
    lets AWS pick a zone that need not offer the instance type, and the follow-up RunJobFlow then
    fails with something that reads exactly like a fidelity defect; an AZ *name* is a per-account
    alias for a different physical zone, so a literal is the same gamble with a fixed spelling. Both
    catalogues are load-bearing (describe_instance_type_offerings does not report zone state,
    describe_availability_zones says nothing about instance types), and the intersection being
    non-empty is asserted, because an empty one means this region cannot run this check at all.

    The rest is EMR's own requirement list for a cluster in a public subnet: DNS resolution and DNS
    hostnames on the VPC, auto-assigned public IPv4 on the subnet, and a default route to an
    internet gateway — without them the instances cannot reach the EMR service endpoint or S3 and
    the cluster never bootstraps.
    """
    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no available AZ in {ctx.region!r} offers {INSTANCE_TYPE}; the offerings were "
        f"{sorted(offered)!r} and the available zones were "
        f"{sorted(z['ZoneName'] for z in ec2.describe_availability_zones()['AvailabilityZones'])!r}"
        f" — this region cannot place the cluster this check needs"
    )
    az = usable[0]

    vpc_id = ec2.create_vpc(CidrBlock=_VPC_CIDR,
                            TagSpecifications=_net_tags(ctx, "vpc"))["Vpc"]["VpcId"]
    # Registered before anything is put INSIDE the VPC, and it deletes the whole estate (EMR's own
    # security groups, the subnet, the gateway, then the VPC), so it stays correct however far the
    # build below got before an abort.
    ctx.on_cleanup(lambda: _require_done(
        f"vpc {vpc_id}", _delete_network(ec2, vpc_id, 45.0), ("GONE",)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_net_tags(ctx, "internet-gateway"),
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _best_effort(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=_net_tags(ctx, "subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    tables = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"]
    assert len(tables) == 1, (
        f"a new VPC must come with exactly one main route table, got "
        f"{[t['RouteTableId'] for t in tables]!r}"
    )
    # No cleanup registered for the route: it lives in the VPC's own main route table, which
    # DeleteVpc removes. A separate delete would be a callable that undoes nothing.
    ec2.create_route(RouteTableId=tables[0]["RouteTableId"],
                     DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["State"],
        lambda st: st == "available",
        timeout_s=120.0,
        interval_s=5.0,
        description=f"subnet {subnet_id} in {az} becoming available",
    )
    return vpc_id, subnet_id


def _delete_network(ec2, vpc_id: str, budget_s: float) -> str:
    """Delete the VPC and everything in it; return "GONE", or what is still standing.

    Retried under one budget rather than attempted once, for two independent reasons:

      * the cluster's ENIs are released asynchronously after its instances terminate, so the first
        DeleteSecurityGroup and DeleteSubnet legitimately return `DependencyViolation`;
      * EMR creates its two default managed security groups ITSELF when RunJobFlow
        names no managed security groups, and gives them rules that reference each other. A delete
        with those rules still in place fails forever rather than eventually, so every rule is
        revoked first. They are inside a VPC this check built, so deleting them cannot disturb a
        sibling run — which is exactly what made them unreclaimable in the default VPC.
    """
    deadline = time.monotonic() + budget_s
    last = "teardown never attempted"
    while True:
        errors: list[str] = []
        try:
            if not ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]:
                return "GONE"
            groups: list[dict] = []
            for page in ec2.get_paginator("describe_security_groups").paginate(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
                groups.extend(page["SecurityGroups"])
            # Revoke every rule on every non-default group FIRST, so no group references another.
            for grp in groups:
                if grp["GroupName"] == "default":
                    continue
                if grp.get("IpPermissions"):
                    _swallow_gone(lambda g=grp: ec2.revoke_security_group_ingress(
                        GroupId=g["GroupId"], IpPermissions=g["IpPermissions"]),
                        errors, f"security group {grp['GroupId']} ingress")
                if grp.get("IpPermissionsEgress"):
                    _swallow_gone(lambda g=grp: ec2.revoke_security_group_egress(
                        GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"]),
                        errors, f"security group {grp['GroupId']} egress")
            for grp in groups:
                if grp["GroupName"] == "default":
                    # Deleted by DeleteVpc itself; it cannot be deleted on its own.
                    continue
                _swallow_gone(lambda g=grp: ec2.delete_security_group(GroupId=g["GroupId"]),
                              errors, f"security group {grp['GroupId']} ({grp['GroupName']})")
            subnets: list[dict] = []
            for page in ec2.get_paginator("describe_subnets").paginate(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
                subnets.extend(page["Subnets"])
            for sub in subnets:
                _swallow_gone(lambda s=sub: ec2.delete_subnet(SubnetId=s["SubnetId"]),
                              errors, f"subnet {sub['SubnetId']}")
            for igw in ec2.describe_internet_gateways(Filters=[
                    {"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]:
                gid = igw["InternetGatewayId"]
                _swallow_gone(lambda i=gid: ec2.detach_internet_gateway(
                    InternetGatewayId=i, VpcId=vpc_id), errors, f"internet gateway {gid} detach")
                _swallow_gone(lambda i=gid: ec2.delete_internet_gateway(InternetGatewayId=i),
                              errors, f"internet gateway {gid} delete")
            held = len(errors)
            _swallow_gone(lambda: ec2.delete_vpc(VpcId=vpc_id), errors, f"vpc {vpc_id}")
            if len(errors) == held:
                return "GONE"
        except ClientError as exc:
            if _already_gone(exc):
                return "GONE"
            raise
        last = "; ".join(errors)[:800]
        if time.monotonic() >= deadline:
            return last
        time.sleep(2)


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _purge_and_delete() -> None:
        # Retried: EMR's log-push agent can flush one more object after the cluster is TERMINATED,
        # and a bucket that is not empty cannot be deleted. A residual bucket is a named leftover,
        # never a silent one.
        last = None
        for _ in range(4):
            try:
                for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                    objs = [
                        {"Key": o["Key"], "VersionId": o["VersionId"]}
                        for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                    ]
                    if objs:
                        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                        if failed:
                            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
                s3.delete_bucket(Bucket=bucket)
                return
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(10)
        raise AssertionError(f"could not delete bucket {bucket!r}: {last}")

    ctx.on_cleanup(_purge_and_delete)


def _cluster_is_gone(exc) -> bool:
    """True only for the error meaning the cluster no longer exists.

    EMR has no ClusterNotFound: describing a reaped cluster is InvalidRequestException. Everything
    else — throttling, a socket timeout, a brief 5xx — must NOT be read as termination, or the wait
    aborts and hands the IAM deletes a cluster that is still assuming the service role.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return (code in ("InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException")
            or "is not valid" in str(exc) or "does not exist" in str(exc))


def _terminate_and_verify(emr, cluster_id: str, budget_s: float) -> str:
    """Terminate and WAIT for the termination to finish; return the terminal state observed.

    Verified inline, not left to on_cleanup: TerminateJobFlows returns immediately while EMR spends
    minutes winding the cluster down, and the cleanup chain is joined on a 60 s daemon thread that
    never affects the verdict — so a bare on_cleanup terminate can leak the EC2 instances behind a
    cluster, at ~$173/mo per node, on a PASSING check.
    """
    try:
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
    except Exception as exc:  # noqa: BLE001
        if not _cluster_is_gone(exc):
            raise
    deadline = time.monotonic() + budget_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            last = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            if _cluster_is_gone(exc):
                return "GONE"
            raise
        if last in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return last
        time.sleep(2)
    return last


def _require_done(what: str, status: str, done: tuple[str, ...]) -> None:
    """Raise when a teardown wait ended with *what* still standing."""
    if status not in done:
        raise AssertionError(f"{what} is still {status!r} after its teardown wait")


def _list_keys(s3, bucket: str, prefix: str) -> list[str]:
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(out)


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Spark step really runs the job: the aggregate Spark computed and the Hive-style
    `dept=<value>` partition layout its writer produced are read back out of S3, with the
    partition column pruned from the record bodies."""
    emr = ctx.client("emr")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    clock = _Deadline(_TOTAL_BUDGET_S)
    nonce = f"sim2real-nonce-{uuid.uuid4().hex[:12]}"

    bucket = ctx.unique_name("sim2real-emr-part-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    csv_body = "dept,amount,run\n" + "".join(f"{d},{a},{nonce}\n" for d, a in _ROWS)
    s3.put_object(Bucket=bucket, Key="input/data.csv", Body=csv_body.encode("utf-8"))
    s3.put_object(Bucket=bucket, Key="job/partitioned_write.py", Body=_SPARK_JOB.encode("utf-8"))

    expected_totals: dict[str, int] = {}
    for dept, amount in _ROWS:
        expected_totals[dept] = expected_totals.get(dept, 0) + amount

    svc_role, ec2_profile = _ensure_emr_roles(ctx, iam)
    vpc_id, subnet_id = _create_network(ctx, ec2)

    out_prefix = "out/agg/"
    step = {
        "Name": "sim2real-partitioned-write",
        "ActionOnFailure": "CONTINUE",
        "HadoopJarStep": {
            "Jar": "command-runner.jar",
            "Args": [
                "spark-submit", "--deploy-mode", "client",
                "--conf", "spark.hadoop.mapreduce.fileoutputcommitter.marksuccessfuljobs=true",
                f"s3://{bucket}/job/partitioned_write.py",
                f"s3://{bucket}/input/",
                f"s3://{bucket}/{out_prefix}",
            ],
        },
    }

    left = ctx.time_left()
    deadline = time.monotonic() + (240 if left is None else min(240, left))
    while True:
        try:
            cluster_id = emr.run_job_flow(
                Name=ctx.unique_name("sim2real-emr-part-cluster-"),
                ReleaseLabel=RELEASE_LABEL,
                LogUri=f"s3://{bucket}/logs/",
                Applications=[{"Name": "Spark"}],
                Instances={
                    "InstanceCount": 2,
                    "MasterInstanceType": INSTANCE_TYPE,
                    "SlaveInstanceType": INSTANCE_TYPE,
                    "Ec2SubnetId": subnet_id,
                    # True, so the cluster does not self-terminate between the step finishing and
                    # the S3 reads below; the verified inline teardown in the finally is what stops
                    # that from leaking.
                    "KeepJobFlowAliveWhenNoSteps": True,
                    "TerminationProtected": False,
                },
                ServiceRole=svc_role,
                JobFlowRole=ec2_profile,
                VisibleToAllUsers=True,
                StepConcurrencyLevel=1,
                Steps=[step],
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )["JobFlowId"]
            break
        except Exception as exc:  # noqa: BLE001
            lowered = str(exc).lower()
            if not any(t in lowered for t in
                       ("throttl", "rate exceeded", "invalid instanceprofile", "invalid ec2")):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    # Failure-path net only; the verified teardown is inline in the finally below.
    ctx.on_cleanup(lambda: _require_done(
        f"cluster {cluster_id}", _terminate_and_verify(emr, cluster_id, 45.0),
        ("TERMINATED", "TERMINATED_WITH_ERRORS", "GONE")))

    body_ok = False
    try:
        def _steps() -> list[dict]:
            found: list[dict] = []
            for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id):
                found.extend(page.get("Steps", []))
            return found

        steps = _poll_until(
            _steps,
            lambda ss: len(ss) == 1 and ss[0]["Status"]["State"] in TERMINAL_STEP_STATES,
            timeout_s=clock.left(_STEP_BUDGET_S),
            interval_s=30.0,
            description=f"the step on cluster {cluster_id} reaching a terminal state",
        )
        step_id = steps[0]["Id"]
        described = emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]

        # 1. the step ran to completion, with a real execution window.
        assert described["Status"]["State"] == "COMPLETED", (
            f"the Spark step ended {described['Status']['State']!r}, expected COMPLETED "
            f"(StateChangeReason {described['Status'].get('StateChangeReason')!r}, "
            f"FailureDetails {described['Status'].get('FailureDetails')!r})"
        )
        timeline = described["Status"]["Timeline"]
        for field in ("CreationDateTime", "StartDateTime", "EndDateTime"):
            assert field in timeline, (
                f"a COMPLETED step must carry Status.Timeline.{field}, got {timeline!r}"
            )
        assert (timeline["CreationDateTime"] <= timeline["StartDateTime"]
                <= timeline["EndDateTime"]), (
            f"step timeline must be ordered creation <= start <= end, got {timeline!r}"
        )

        # 2. the job marker the step's own conf asked for.
        keys = _poll_until(
            lambda: _list_keys(s3, bucket, out_prefix),
            lambda ks: f"{out_prefix}_SUCCESS" in ks,
            timeout_s=clock.left(_OUTPUT_BUDGET_S),
            interval_s=5.0,
            description=(
                f"the Spark writer's _SUCCESS marker under s3://{bucket}/{out_prefix} "
                f"(marksuccessfuljobs=true was passed to this step)"
            ),
        )

        # 3. exactly the Hive-style partition directories, one visible part file each.
        layout: dict[str, list[str]] = {}
        for key in keys:
            rel = key[len(out_prefix):]
            if "/" not in rel:
                assert rel == "_SUCCESS", (
                    f"unexpected object directly under the output prefix: {key!r} "
                    f"(all of them: {keys!r})"
                )
                continue
            part_dir, base = rel.split("/", 1)
            # Committer scratch (`_temporary/...`) and hidden files are not the subject here.
            if part_dir.startswith((".", "_")) or base.startswith((".", "_")):
                continue
            layout.setdefault(part_dir, []).append(base)
        assert set(layout) == {f"dept={d}" for d in expected_totals}, (
            f"the output layout is {sorted(layout)!r}; Spark's partitionBy('dept') must produce "
            f"exactly the Hive-style directories "
            f"{sorted('dept=' + d for d in expected_totals)!r} for the uploaded input"
        )
        for part_dir, bases in sorted(layout.items()):
            assert len(bases) == 1, (
                f"partition {part_dir!r} holds {len(bases)} part files {sorted(bases)!r}; "
                f"repartition(1) must write exactly one"
            )
            assert bases[0].startswith("part-") and bases[0].endswith(".json"), (
                f"partition {part_dir!r} holds {bases[0]!r}, not a Spark JSON part file"
            )

        # 4/5. the aggregate Spark computed, and the partition column pruned out of the body.
        for dept, expected_total in sorted(expected_totals.items()):
            key = f"{out_prefix}dept={dept}/{layout['dept=' + dept][0]}"
            raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
            lines = [ln for ln in raw.splitlines() if ln.strip()]
            assert len(lines) == 1, (
                f"{key!r} holds {len(lines)} JSON records, expected exactly the one aggregated row "
                f"for dept={dept!r}: {raw!r}"
            )
            record = json.loads(lines[0])
            assert record.get("total") == expected_total, (
                f"{key!r} reports total {record.get('total')!r} for dept={dept!r}; Spark must have "
                f"summed the uploaded rows to {expected_total!r}. Record: {record!r}"
            )
            assert record.get("run") == nonce, (
                f"{key!r} carries run={record.get('run')!r}, not this run's nonce {nonce!r} — the "
                f"output did not come from the input this check uploaded"
            )
            assert set(record) == {"total", "run"}, (
                f"{key!r} has fields {sorted(record)!r}; the partitioning column 'dept' is pruned "
                f"into the path by Spark and must NOT also appear in the record body, or a "
                f"partition-discovery reader double-counts it"
            )
        body_ok = True
    finally:
        # Always terminate and always WAIT for it, then delete the network the cluster sat in —
        # both inline rather than left to on_cleanup, whose whole chain is bounded at 60 s from
        # outside (DEFAULT_CLEANUP_TIMEOUT_S) and never affects the verdict. Only assert the leak
        # claims when the body itself succeeded, so a teardown assertion can never mask the
        # fidelity failure that caused it.
        state = _terminate_and_verify(
            emr, cluster_id, max(clock.left(_TEARDOWN_BUDGET_S), _TEARDOWN_FLOOR_S))
        # After the cluster, never before: the VPC cannot go while its instances hold ENIs in it.
        network = _delete_network(
            ec2, vpc_id,
            max(clock.left(_NETWORK_TEARDOWN_BUDGET_S), _NETWORK_TEARDOWN_FLOOR_S))
        if body_ok:
            assert state in ("TERMINATED", "TERMINATED_WITH_ERRORS", "GONE"), (
                f"cluster {cluster_id} is still {state!r} after the verified teardown wait — every "
                f"provisioned {INSTANCE_TYPE} is ~$173/mo and reap_leftovers.py cannot terminate it"
            )
            assert network == "GONE", (
                f"the VPC {vpc_id} this check built is still standing after the teardown wait: "
                f"{network} — it is this check's own resource and nothing else will reclaim it"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
