"""create-cluster-port-outside-valid-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-port-outside-valid-range-rejected"
GROUP = "cluster-lifecycle"
SERVICES = ["neptune"]

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
    """CreateDBCluster rejects a Port below the documented 1150-65535 range with its exact
    message, creating no cluster, while the minimum valid Port is accepted.
    """
    neptune = ctx.client("neptune")
    network = ctx.network()
    below_min_id = ctx.unique_name("sim2real-neptune-portlo-")
    min_id = ctx.unique_name("sim2real-neptune-portmin-")
    subnet_group_name = ctx.unique_name("sim2real-neptune-portrange-sng-")

    neptune.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real neptune port range validation check",
        SubnetIds=network.subnet_ids,
        Tags=[{"Key": "Name", "Value": subnet_group_name}],
    )
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
        "DBSubnetGroupNotFoundFault",
    ))

    expect_error(
        lambda: neptune.create_db_cluster(
            DBClusterIdentifier=below_min_id, Engine="neptune", Port=_BELOW_MIN_PORT,
            DBSubnetGroupName=subnet_group_name,
        ),
        *_RANGE_ERROR,
    )
    # ----- the refused identifier was never created -----
    rejected_code, rejected_message = None, None
    try:
        neptune.describe_db_clusters(DBClusterIdentifier=below_min_id)
    except ClientError as exc:
        rejected_code = exc.response["Error"]["Code"]
        rejected_message = exc.response["Error"]["Message"]
    assert rejected_code == "DBClusterNotFoundFault", (
        f"the refused create must not have left a cluster behind; describe returned "
        f"code={rejected_code!r}"
    )
    assert rejected_message == f"DBCluster {below_min_id} not found.", rejected_message

    # ----- the minimum valid Port is accepted (the legal neighbour) -----
    created = neptune.create_db_cluster(
        DBClusterIdentifier=min_id, Engine="neptune", Port=_MIN_PORT,
        DBSubnetGroupName=subnet_group_name,
    )["DBCluster"]
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_cluster(DBClusterIdentifier=min_id, SkipFinalSnapshot=True),
        "DBClusterNotFoundFault",
    ))
    assert created["Port"] == _MIN_PORT, created

    described = neptune.describe_db_clusters(DBClusterIdentifier=min_id)["DBClusters"]
    assert len(described) == 1, described
    assert described[0]["Port"] == _MIN_PORT, described[0]

    neptune.delete_db_cluster(DBClusterIdentifier=min_id, SkipFinalSnapshot=True)
    gone_code, gone_message = _await_cluster_gone(neptune, min_id)
    assert gone_code == "DBClusterNotFoundFault", gone_code
    assert gone_message == f"DBCluster {min_id} not found.", gone_message


def _await_cluster_gone(neptune, cluster_id, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err["Message"]
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id!r} never disappeared within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
