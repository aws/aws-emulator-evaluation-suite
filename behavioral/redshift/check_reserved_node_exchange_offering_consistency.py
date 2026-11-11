"""reserved-node-exchange-offering-consistency."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-node-exchange-offering-consistency"
GROUP = "server-side"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Exchange lookups resolve real resources: an unknown ReservedNodeId gives
    ReservedNodeNotFound, an unknown cluster ClusterNotFound, an owned non-DS2 cluster
    UnsupportedOperation, each with its exact message."""
    # Reference: https://docs.aws.amazon.com/redshift/latest/APIReference/API_GetReservedNodeExchangeConfigurationOptions.html
    redshift = ctx.client("redshift")

    resp = redshift.describe_reserved_nodes()
    assert "ReservedNodes" in resp

    # ReservedNodeId is UUID-shaped; a non-UUID string fails with InvalidParameterValue
    # before the existence check runs.
    bogus_reserved_node_id = str(uuid.uuid4())
    offerings_code, offerings_message = _error(
        lambda: redshift.get_reserved_node_exchange_offerings(
            ReservedNodeId=bogus_reserved_node_id
        )
    )
    assert offerings_code == "ReservedNodeNotFound", offerings_code
    expected_offerings = f"Reserved Node {bogus_reserved_node_id} not found."
    assert offerings_message == expected_offerings, (
        f"expected message {expected_offerings!r}, got {offerings_message!r}"
    )

    # A real non-DS2 cluster: UnsupportedOperation is only raised after the identifier
    # resolves to a cluster and its node type is inspected.
    cluster_id = ctx.unique_name("sim2real-rnc-")
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    redshift.create_cluster(**_cluster_params(redshift, cluster_id))
    _wait_for_cluster_available(redshift, cluster_id)

    real_cluster_code, real_cluster_message = _error(
        lambda: redshift.get_reserved_node_exchange_configuration_options(
            ActionType="resize-cluster", ClusterIdentifier=cluster_id
        )
    )
    assert real_cluster_code == "UnsupportedOperation", real_cluster_code
    expected_real = "You can only exchange DS2 reserved nodes."
    assert real_cluster_message == expected_real, (
        f"expected message {expected_real!r}, got {real_cluster_message!r}"
    )

    # ActionType="resize-cluster" is the exchange path sourced from a live
    # cluster (ClusterIdentifier); "restore-cluster" is sourced from a
    # snapshot (SnapshotIdentifier) and rejects ClusterIdentifier-only input
    # with InvalidParameterCombination before ever checking existence.
    bogus_cluster_id = ctx.unique_name("sim2real-rnc-nonexistent-")
    options_code, options_message = _error(
        lambda: redshift.get_reserved_node_exchange_configuration_options(
            ActionType="resize-cluster",
            ClusterIdentifier=bogus_cluster_id,
        )
    )
    assert options_code == "ClusterNotFound", options_code
    expected_options = f"The cluster {bogus_cluster_id} was not found."
    assert options_message == expected_options, (
        f"expected message {expected_options!r}, got {options_message!r}"
    )


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"


def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
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
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        # Some accounts require encryption at rest by policy.
        Encrypted=True,
        # RA3 node types refuse retention 0, so use the 1-day minimum.
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    params.update(overrides)
    return params


def _cluster_status(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _wait_until(probe, done, timeout_s=600, interval_s=15, what="condition"):
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=15,
        what=f"cluster {cluster_id} status in {sorted(str(t) for t in terminal)}",
    )
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _delete_cluster(rs, cluster_id):
    """Teardown: a cluster still 'creating' may refuse deletion, so
    retry within a bounded window."""
    deadline = time.time() + 240
    while True:
        try:
            _retrying(lambda: rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True))
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.time() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
