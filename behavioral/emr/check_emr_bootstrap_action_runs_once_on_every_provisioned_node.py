"""emr-bootstrap-action-runs-once-on-every-provisioned-node."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "emr-bootstrap-action-runs-once-on-every-provisioned-node"
GROUP = 'data-plane'
SERVICES = ['emr']

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"
_CORE_COUNT = 2
_EXPECTED_NODES = 1 + _CORE_COUNT

_SCENARIO = "emr-bootstrap-per-node"
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

_CLUSTER_GONE_CODES = ("InvalidRequestException", "ClusterNotFound",
                       "ResourceNotFoundException", "EntityNotFoundException")

# The bootstrap action. It identifies the node it is running on from IMDSv2 -- the node's own view
# of itself, not anything EMR told the check -- and reports its EMR role from
# /mnt/var/lib/info/instance.json, the file EMR documents as available to bootstrap actions.
# The grep matches the role field under the name AWS gives it in that file; the label this script
# writes is the check's own.
#
# One object per node, keyed by instance id, is what makes "ran once per node" observable at all:
# a script that appends to a single key could not distinguish three runs from one, and a script
# keyed by anything the check chose could not distinguish three nodes from one node running
# three times.
_BOOTSTRAP = '''#!/bin/bash
set -eu
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \\
  -H "X-aws-ec2-metadata-token-ttl-seconds: 120")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \\
  http://169.254.169.254/latest/meta-data/instance-id)
ROLE=core
if grep -q '"isMaster": *true' /mnt/var/lib/info/instance.json; then
  ROLE=primary
fi
printf '%s' "$ROLE" > "/tmp/node-$IID"
aws s3 cp "/tmp/node-$IID" "s3://__BUCKET__/nodes/$IID" --region __REGION__
'''


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


def _delete_with_retry(ctx, fn):
    """Run an IAM delete, retrying DeleteConflict every 2 s until the run's cleanup deadline.

    Even once the cluster reports TERMINATED, IAM can briefly still see the instance profile as in
    use, so the delete is retried rather than leaking the role; at the deadline the last
    DeleteConflict is raised.
    """
    from botocore.exceptions import ClientError

    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DeleteConflict" or _cleanup_spent(ctx):
                raise
        time.sleep(2)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile. Returns (service_role, ec2_role).

    EMR_DefaultRole and EMR_EC2_DefaultRole do not exist in a fresh account, so
    pointing at them would surface as an untagged ClientError rather than as EMR behaviour.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-ba-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-ba-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(ctx, lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(ctx, lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        ctx, lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    return svc_role, ec2_role


def _make_bucket(ctx, s3):
    """Create the scratch/log bucket. Registered BEFORE the cluster so LIFO empties it AFTER the
    cluster is gone -- EMR keeps writing step logs into LogUri right up to termination."""
    bucket = ctx.unique_name("sim2real-behav-emr-ba-")

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
    InvalidRequestException. Throttling or a brief 5xx must NOT be read as termination, or the IAM
    deletions would run against a cluster still assuming the service role.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(ctx, emr, cluster_id):
    """Terminate the cluster and WAIT for the termination to finish.

    TerminateJobFlows returns immediately while EMR spends minutes winding the cluster down, and it
    needs the service role for that whole window. Cleanups run LIFO with the IAM deletions
    registered BEFORE the cluster, so a bare terminate would let delete_role run while EMR is still
    using it -- stranding EC2 instances behind a cluster EMR can no longer tear down. Bounded by
    the run's cleanup deadline: if the wait runs out the teardown raises.
    """
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    deadline = _cleanup_deadline(ctx)
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
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
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
        lambda: _terminate_and_await_teardown(ctx, emr, cluster_id))
    return cluster_id


# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3", "cap:c5")
def run(ctx) -> None:
    """A bootstrap action runs exactly once on EVERY provisioned node: the set of S3 objects the
    script wrote, keyed by each node's own IMDS instance id, equals the set of Ec2InstanceIds
    ListInstances reports, and the self-reported primary is the one in the "MASTER" group."""
    emr = ctx.client("emr")
    s3 = ctx.client("s3")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _private_network(ctx, INSTANCE_TYPE)[1]
    bucket = _make_bucket(ctx, s3)

    script_key = "bootstrap/report_node.sh"
    script = _BOOTSTRAP.replace("__BUCKET__", bucket).replace("__REGION__", ctx.region)
    s3.put_object(Bucket=bucket, Key=script_key, Body=script.encode("utf-8"))

    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emr-ba-"),
        ReleaseLabel=RELEASE_LABEL,
        LogUri=f"s3://{bucket}/logs/",
        Instances={
            "InstanceGroups": [
                {"Name": "sim2real-primary", "InstanceRole": "MASTER",
                 "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND"},
                {"Name": "sim2real-core", "InstanceRole": "CORE",
                 "InstanceType": INSTANCE_TYPE, "InstanceCount": _CORE_COUNT,
                 "Market": "ON_DEMAND"},
            ],
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
            "Ec2SubnetId": subnet,
        },
        BootstrapActions=[{"Name": "sim2real-report-node",
                           "ScriptBootstrapAction": {"Path": f"s3://{bucket}/{script_key}"}}],
        Applications=[{"Name": "Hadoop"}],
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    def _cluster():
        return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]

    state = _poll(lambda: _cluster()["Status"]["State"],
                  lambda s: s not in ("STARTING", "BOOTSTRAPPING"),
                  timeout_s=1400, interval_s=20,
                  description=f"EMR cluster {cluster_id} finishing bootstrap")
    assert state == "WAITING", (
        f"the cluster must finish its bootstrap action and reach WAITING; got {state!r} "
        f"({_cluster()['Status'].get('StateChangeReason')!r}). A bootstrap action that exits "
        f"non-zero on any node lands the cluster in TERMINATED_WITH_ERRORS instead."
    )

    # Paginated, because a shared account can hold other clusters' instances and because a
    # membership assertion on page one is not a membership assertion.
    instances = [i for page in emr.get_paginator("list_instances").paginate(ClusterId=cluster_id)
                 for i in page.get("Instances", [])]
    listed_ids = sorted(i["Ec2InstanceId"] for i in instances)
    assert len(listed_ids) == _EXPECTED_NODES, (
        f"ListInstances must report exactly the {_EXPECTED_NODES} nodes requested "
        f"(1 primary + {_CORE_COUNT} core), got {len(listed_ids)}: "
        f"{[(i['Ec2InstanceId'], i['Status']['State']) for i in instances]!r}"
    )
    assert len(set(listed_ids)) == len(listed_ids), (
        f"ListInstances must not repeat an Ec2InstanceId, got {listed_ids!r}"
    )

    # The bootstrap objects land while the cluster is still bootstrapping, so this is a short poll
    # against S3 read-after-write lag, not a second wait for the action.
    def _node_objects():
        return {o["Key"].rsplit("/", 1)[-1]: o["Key"]
                for page in s3.get_paginator("list_objects_v2").paginate(
                    Bucket=bucket, Prefix="nodes/")
                for o in page.get("Contents", [])}

    found = _poll(_node_objects, lambda m: len(m) >= _EXPECTED_NODES,
                  timeout_s=180, interval_s=10,
                  description=f"{_EXPECTED_NODES} bootstrap reports under s3://{bucket}/nodes/")

    # THE assertion: set equality between what ran on the nodes and what the control plane lists.
    assert sorted(found) == listed_ids, (
        f"the bootstrap action must run on every provisioned node and only on those nodes.\n"
        f"  ListInstances Ec2InstanceIds: {listed_ids!r}\n"
        f"  instance ids that reported:   {sorted(found)!r}"
    )
    assert len(found) == _EXPECTED_NODES, (
        f"exactly {_EXPECTED_NODES} objects must exist, one per node -- a bootstrap action that "
        f"ran twice on one node, or only on the primary, fails here; got {sorted(found)!r}"
    )

    roles = {iid: s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8").strip()
             for iid, key in found.items()}
    assert sorted(roles.values()) == sorted(["primary"] + ["core"] * _CORE_COUNT), (
        f"each node must report its own EMR role, so exactly one primary and {_CORE_COUNT} core; "
        f"got {roles!r}"
    )

    # And the roles must agree with EMR's own view of which instance is which, so the script's
    # self-report is cross-checked rather than trusted.
    emr_roles = {i["Ec2InstanceId"]: i["InstanceGroupId"] for i in instances}
    primary_group = next(g["Id"] for page in emr.get_paginator("list_instance_groups").paginate(
        ClusterId=cluster_id) for g in page.get("InstanceGroups", [])
        if g["InstanceGroupType"] == "MASTER")
    reported_primary = [iid for iid, role in roles.items() if role == "primary"]
    assert len(reported_primary) == 1 and emr_roles[reported_primary[0]] == primary_group, (
        f"the node that reported itself as the primary must be the one EMR places in the 'MASTER' "
        f"instance group; the primary group is {primary_group!r}, the reporting node(s) were "
        f"{reported_primary!r} in groups {emr_roles!r}"
    )


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route, and a gateway
#: endpoint to S3 (all EMR needs there) is the only way out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: One teardown deadline per run, inside the suite's 900 s cleanup budget, started by the first
#: teardown that asks for it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 840.0
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
