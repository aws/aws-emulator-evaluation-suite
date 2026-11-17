"""modify-cluster-port-outside-valid-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cluster-port-outside-valid-range-rejected"
GROUP = "cluster-lifecycle"
SERVICES = ["neptune"]

_STARTING_PORT = 8182
_MIN_PORT = 1150
_BELOW_MIN_PORT = 1149

_RANGE_ERROR = (
    "InvalidParameterValue",
    f"Invalid endpoint port {_BELOW_MIN_PORT}. Valid range is: {_MIN_PORT}-65535 ",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Asserts ``fn()`` raises a ClientError with exactly ``code`` and ``message``."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected code {code!r}, got {err['Code']!r}: {err.get('Message')!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyDBCluster rejects a Port below the documented 1150-65535 range with its exact
    message, leaving the cluster's own port unchanged, while the minimum valid Port is applied.
    """
    neptune = ctx.client("neptune")
    network = ctx.network()
    cluster_id = ctx.unique_name("sim2real-neptune-modportrange-")
    subnet_group_name = ctx.unique_name("sim2real-neptune-modportrange-sng-")

    neptune.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real neptune modify port range validation check",
        SubnetIds=network.subnet_ids,
        Tags=[{"Key": "Name", "Value": subnet_group_name}],
    )
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
        "DBSubnetGroupNotFoundFault",
    ))

    created = neptune.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="neptune",
        Port=_STARTING_PORT,
        DBSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "Name", "Value": cluster_id}],
    )["DBCluster"]
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        "DBClusterNotFoundFault",
    ))
    assert created["Port"] == _STARTING_PORT, created

    cluster = _await_cluster_status(neptune, cluster_id, "available")
    assert cluster["Port"] == _STARTING_PORT, cluster

    # ----- ModifyDBCluster(Port=1149) is refused -----
    expect_error(
        lambda: neptune.modify_db_cluster(
            DBClusterIdentifier=cluster_id, Port=_BELOW_MIN_PORT, ApplyImmediately=True,
        ),
        *_RANGE_ERROR,
    )

    # ----- the refused modify left the cluster's own port unchanged -----
    unchanged = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert unchanged["Port"] == _STARTING_PORT, (
        f"a refused ModifyDBCluster(Port={_BELOW_MIN_PORT!r}) must leave the cluster's port at "
        f"{_STARTING_PORT!r}, got {unchanged['Port']!r}"
    )

    # ----- the minimum valid Port, the legal neighbour, is accepted -----
    neptune.modify_db_cluster(
        DBClusterIdentifier=cluster_id, Port=_MIN_PORT, ApplyImmediately=True,
    )
    cluster = _await_cluster_status(neptune, cluster_id, "available")
    assert cluster["Port"] == _MIN_PORT, cluster

    described = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert described["Port"] == _MIN_PORT, described

    neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    gone_code, gone_message = _await_cluster_gone(neptune, cluster_id)
    assert gone_code == "DBClusterNotFoundFault", gone_code
    assert gone_message == f"DBCluster {cluster_id} not found.", gone_message


def _await_cluster_status(neptune, cluster_id, want_status, timeout_s=600):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["Status"] == want_status:
            return desc
        time.sleep(5)
    raise AssertionError(
        f"cluster {cluster_id!r} never reached {want_status!r} within {timeout_s}s "
        f"(last status={desc['Status'] if desc else None!r})"
    )


def _await_cluster_gone(neptune, cluster_id, timeout_s=600):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err["Message"]
        time.sleep(5)
    raise AssertionError(f"cluster {cluster_id!r} never disappeared within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
