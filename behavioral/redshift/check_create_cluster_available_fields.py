"""create-cluster-available-fields."""

from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


_POLL_INTERVAL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``.

    A call that succeeds raises ``AssertionError``: the refusal is the claim."""
    try:
        _retrying(fn)
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_until(probe, done, timeout_s=600, interval_s=_POLL_INTERVAL_S, what="condition", ctx=None):
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"
PARAM_FAMILY = "redshift-1.0"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _cluster_params(rs, cluster_id, **overrides):
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=MASTER_USERNAME,
        MasterUserPassword=MASTER_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        # The request asks for an encrypted cluster.
        Encrypted=True,
        # RA3 node types refuse retention 0, so use the 1-day minimum.
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    params.update(overrides)
    return params


def _describe_cluster(rs, cluster_id):
    resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    clusters = resp.get("Clusters", [])
    return clusters[0] if clusters else None


def _cluster_status(rs, cluster_id):
    try:
        cluster = _describe_cluster(rs, cluster_id)
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    return cluster["ClusterStatus"] if cluster else None


def _wait_for_cluster_status(rs, cluster_id, target_statuses, timeout_s=600, interval_s=_POLL_INTERVAL_S, ctx=None):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} status in {sorted(str(t) for t in targets)}",
        ctx=ctx,
    )


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600, ctx=None):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_for_cluster_status(rs, cluster_id, terminal, timeout_s=timeout_s, ctx=ctx)
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _wait_for_cluster_gone(rs, cluster_id, timeout_s=420, interval_s=_POLL_INTERVAL_S, ctx=None):
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} to disappear",
        ctx=ctx,
    )


def _delete_cluster(rs, cluster_id, gone_timeout_s=900, ctx=None):
    """Teardown: a cluster still 'creating' refuses deletion with InvalidClusterState, so
    retry that within a bounded window and raise once it passes, then wait for the
    cluster to be gone so its subnet group and VPC can be removed."""
    deadline = time.time() + 240
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            code = _code_of(exc)
            if code in _NOT_FOUND_CLUSTER:
                return
            if code != "InvalidClusterState":
                raise
            if _cluster_status(rs, cluster_id) in ("deleting", None):
                break
            if time.time() >= deadline:
                raise AssertionError(
                    f"DeleteCluster on {cluster_id} still refused after 240s: {exc}"
                ) from exc
        time.sleep(_POLL_INTERVAL_S)
    _wait_for_cluster_gone(rs, cluster_id, timeout_s=gone_timeout_s, ctx=ctx)


def _create_network(ctx, rs):
    """A VPC, one subnet and a cluster subnet group owned by this check; returns
    ``(vpc_id, subnet_group_name, teardown)``. ``teardown(wait_s)`` removes them in
    dependency order, retrying while the deleted cluster's network interface lingers;
    run() calls it once the cluster is gone, and the registered cleanup repeats it."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-rs-vpc-")}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    made = {"vpc": vpc_id}

    def _teardown(wait_s=600.0, run_ctx=None):
        deadline = time.time() + wait_s
        steps = []
        if "group" in made:
            steps.append(lambda: rs.delete_cluster_subnet_group(ClusterSubnetGroupName=made["group"]))
        if "subnet" in made:
            steps.append(lambda: ec2.delete_subnet(SubnetId=made["subnet"]))
        steps.append(lambda: ec2.delete_vpc(VpcId=vpc_id))
        for step in steps:
            while True:
                try:
                    step()
                    break
                except ClientError as exc:
                    code = _code_of(exc)
                    if code in _GONE_NETWORK:
                        break
                    if code not in _BUSY_NETWORK:
                        raise
                    if time.time() >= deadline:
                        if run_ctx is not None and _budget_spent(run_ctx):
                            raise TimeoutError(
                                f"network of {vpc_id} released: the run budget ended first; not graded"
                            ) from exc
                        raise
                    time.sleep(_POLL_INTERVAL_S)

    ctx.on_cleanup(_teardown)
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.0.0.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    made["subnet"] = subnet_id
    group = ctx.unique_name("sim2real-behav-rs-subg-")
    _retrying(lambda: rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=group,
        Description="sim2real behavioral fidelity check",
        SubnetIds=[subnet_id],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))
    made["group"] = group
    return vpc_id, group, _teardown


_GONE_NETWORK = ("ClusterSubnetGroupNotFoundFault", "InvalidSubnetID.NotFound", "InvalidVpcID.NotFound")
_BUSY_NETWORK = ("DependencyViolation", "InvalidClusterSubnetGroupStateFault")

MSG_RESIZE_NOT_FOUND = "No Resize found for Cluster {cluster_id}"

CHECK = "create-cluster-available-fields"
GROUP = 'cluster-lifecycle'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster goes creating -> available with no endpoint until available, in the check's VPC,
    with the documented identity/default fields, audit logging off, DB revisions present, no resize.
    """
    rs = ctx.client("redshift")
    vpc_id, subnet_group, delete_network = _create_network(ctx, rs)
    cluster_id = ctx.unique_name("sim2real-behav-rs-create-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    created = rs.create_cluster(
        **_cluster_params(rs, cluster_id, ClusterSubnetGroupName=subnet_group)
    )["Cluster"]

    assert created["ClusterIdentifier"] == cluster_id
    assert created["ClusterStatus"] == "creating", f"expected creating, got {created['ClusterStatus']}"
    assert created["NodeType"] == _node_type(rs)
    assert created["MasterUsername"] == MASTER_USERNAME
    assert created["DBName"] == "devdb"
    assert created["Encrypted"] is True, "this account mandates encryption at rest"
    assert not created.get("Endpoint", {}).get("Address"), (
        f"a creating cluster must not expose an endpoint yet, got {created.get('Endpoint')}"
    )

    _wait_for_cluster_available(rs, cluster_id, timeout_s=_budget_s(ctx, 660), ctx=ctx)

    cluster = _describe_cluster(rs, cluster_id)
    assert cluster is not None, "describe_clusters returned no cluster"
    assert cluster["ClusterStatus"] == "available"
    assert cluster["NodeType"] == _node_type(rs)
    assert cluster["MasterUsername"] == MASTER_USERNAME
    assert cluster["DBName"] == "devdb"
    assert cluster["NumberOfNodes"] == 1, f"single-node cluster must report 1 node, got {cluster['NumberOfNodes']}"
    assert cluster["AutomatedSnapshotRetentionPeriod"] == 1
    assert cluster["Encrypted"] is True
    assert cluster.get("KmsKeyId"), "an encrypted cluster must report the KMS key it uses"
    address = cluster["Endpoint"]["Address"] or ""
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", address), cluster["Endpoint"]
    assert cluster["Endpoint"]["Port"] > 0
    assert cluster["VpcId"] == vpc_id, f"expected the cluster in VPC {vpc_id}, got {cluster.get('VpcId')}"
    assert cluster["ClusterSubnetGroupName"] == subnet_group, cluster.get("ClusterSubnetGroupName")
    assert cluster["ClusterParameterGroups"][0]["ParameterApplyStatus"] == "in-sync"
    assert cluster.get("ClusterCreateTime") is not None

    logging_status = rs.describe_logging_status(ClusterIdentifier=cluster_id)
    assert logging_status["LoggingEnabled"] is False, "audit logging must default to disabled"

    revisions = rs.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)["ClusterDbRevisions"]
    assert revisions and revisions[0]["ClusterIdentifier"] == cluster_id

    storage = rs.describe_storage()
    assert "TotalBackupSizeInMegaBytes" in storage, storage

    code, message = _refusal(lambda: rs.describe_resize(ClusterIdentifier=cluster_id))
    assert code == "ResizeNotFound", f"expected ResizeNotFound on a never-resized cluster, got {code}"
    expected = MSG_RESIZE_NOT_FOUND.format(cluster_id=cluster_id)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The network can only be removed once the cluster is gone; that wait is longer than
    # the teardown budget, so it happens here.
    _delete_cluster(rs, cluster_id, gone_timeout_s=_budget_s(ctx, 900), ctx=ctx)
    delete_network(wait_s=_budget_s(ctx, 600.0), run_ctx=ctx)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
