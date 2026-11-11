"""parameter-group-delete-default-fails."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


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


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}


def _error(fn):
    """Call *fn* and return the (code, message) of the AWS error it raises; a success fails."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call succeeded where AWS rejects it")


NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")


def _single_node_types(rs):
    node_types = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != "single-node":
                continue
            nt = opt.get("NodeType")
            if nt and nt not in node_types:
                node_types.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    if not node_types:
        raise AssertionError("no orderable single-node cluster options in this region")
    return node_types


def _delete_cluster_bestof(rs, cluster_id, timeout_s=240):
    """A cluster still `creating` refuses deletion with InvalidClusterState: retry that every 2 s
    to the deadline; a cluster already `deleting` is done; any other refusal raises."""
    deadline = time.time() + timeout_s
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState":
                raise
            try:
                status = rs.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"]
            except ClientError as dexc:
                if _code_of(dexc) in _NOT_FOUND_CLUSTER:
                    return
                raise
            if status == "deleting":
                return
            if time.time() >= deadline:
                raise
        time.sleep(2)


# The ClusterDeleted waiter allows 1800 s, the redshift teardown budget; keep a 60 s margin.
_TEARDOWN_S = 1740.0


def _delete_cluster(rs, cluster_id):
    """Teardown: DeleteCluster, retrying InvalidClusterState (creating or already deleting) every
    2 s, then poll every 2 s until ClusterNotFound, since the delete is asynchronous; one deadline."""
    deadline = time.monotonic() + _TEARDOWN_S
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            rs.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"cluster {cluster_id} still listed at the teardown deadline")
        time.sleep(2)


def _delete_parameter_group(rs, name):
    """Teardown: the body deletes the control group itself, so an absent group is done."""
    try:
        rs.delete_cluster_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if _code_of(exc) not in ("ClusterParameterGroupNotFound", "ClusterParameterGroupNotFoundFault"):
            raise


def _materialize_default_group(ctx, rs):
    """A freshly-provisioned account exposes no `default.*` parameter group until its first
    cluster is created — AWS materializes `default.<family>` lazily, at CreateCluster time, not
    ahead of it. Create-or-adopt: a throwaway single-node cluster if the account has none yet.

    The seed cluster's delete starts here, so it runs while the rest of the check does; the
    teardown waits until the cluster is gone."""
    node_types = _single_node_types(rs)
    node_type = next((nt for nt in NODE_TYPE_PREFERENCE if nt in node_types), sorted(node_types)[0])
    cluster_id = ctx.unique_name("sim2real-behav-rs-pg-seed-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=node_type,
        MasterUsername="adminuser",
        MasterUserPassword="TestPassw0rd123",
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    _delete_cluster_bestof(rs, cluster_id, timeout_s=220)


CHECK = "parameter-group-delete-default-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting the service-owned `default.*` parameter group is rejected with InvalidParameterValue
    and its exact message and the group remains, while an ordinary group deletes and then answers
    ClusterParameterGroupNotFound with its exact message."""
    rs = ctx.client("redshift")

    control_name = ctx.unique_name("sim2real-behav-rs-pg-")
    ctx.on_cleanup(lambda: _delete_parameter_group(rs, control_name))
    rs.create_cluster_parameter_group(
        ParameterGroupName=control_name,
        ParameterGroupFamily="redshift-1.0",
        Description="behavioral positive-control group",
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    control_delete_code = _err(lambda: rs.delete_cluster_parameter_group(ParameterGroupName=control_name))
    assert control_delete_code == "OK", (
        f"deleting an ordinary, non-default parameter group must succeed, got {control_delete_code}"
    )
    control_gone_code, control_gone_message = _error(
        lambda: rs.describe_cluster_parameter_groups(ParameterGroupName=control_name)
    )
    assert control_gone_code == "ClusterParameterGroupNotFound", (
        f"deleted control group {control_name} must be gone from describe, got {control_gone_code}"
    )
    assert control_gone_message == f"ClusterParameterGroup {control_name} not found.", control_gone_message

    groups = rs.describe_cluster_parameter_groups(MaxRecords=100)["ParameterGroups"]
    default_groups = [g["ParameterGroupName"] for g in groups if g["ParameterGroupName"].startswith("default.")]
    if not default_groups:
        _materialize_default_group(ctx, rs)
        groups = rs.describe_cluster_parameter_groups(MaxRecords=100)["ParameterGroups"]
        default_groups = [g["ParameterGroupName"] for g in groups if g["ParameterGroupName"].startswith("default.")]
    if not default_groups:
        raise AssertionError(
            "account still exposes no default.* parameter group after creating a cluster to seed "
            f"one; full describe_cluster_parameter_groups()={groups!r}"
        )

    target = sorted(default_groups)[0]
    code, message = _error(lambda: rs.delete_cluster_parameter_group(ParameterGroupName=target))
    assert code == "InvalidParameterValue", (
        f"deleting the service-owned {target} must be rejected with InvalidParameterValue, got {code}"
    )
    assert message == f"The Cluster Parameter Group cannot be deleted: {target}", message
    still_there = rs.describe_cluster_parameter_groups(ParameterGroupName=target)["ParameterGroups"]
    assert len(still_there) == 1, f"{target} must survive the rejected delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
