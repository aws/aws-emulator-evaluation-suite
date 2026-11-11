"""concurrent-modify-db-cluster-conflicting-state-rejected."""
from __future__ import annotations

import secrets
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-modify-db-cluster-conflicting-state-rejected"
GROUP = "concurrency"
SERVICES = ["rds"]

_STATE_MESSAGE = "This cluster could not be modified. Please try again"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two simultaneous ModifyDBCluster calls on one cluster: a refused call gets only
    InvalidDBClusterStateFault with its exact message, and the final BackupRetentionPeriod is a
    successful writer's."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-modrace-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBSubnetGroupName=subnet_group,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    target_a, target_b = 3, 9

    def _modify_a():
        rds.modify_db_cluster(
            DBClusterIdentifier=cluster_id, BackupRetentionPeriod=target_a, ApplyImmediately=True
        )
        return target_a

    def _modify_b():
        rds.modify_db_cluster(
            DBClusterIdentifier=cluster_id, BackupRetentionPeriod=target_b, ApplyImmediately=True
        )
        return target_b

    result_a, result_b = _race_two(_modify_a, _modify_b)

    outcomes = [result_a, result_b]
    written = [r["value"] for r in outcomes if r["ok"]]
    refused = [(r["code"], r["message"]) for r in outcomes if not r["ok"]]
    assert written, f"expected at least one ModifyDBCluster racer to succeed: {outcomes!r}"
    # An overlapping modify may be refused; serialized modifies both succeed.
    expected_refusal = ("InvalidDBClusterStateFault", _STATE_MESSAGE)
    assert all(error == expected_refusal for error in refused), (
        f"a refused racer must get {expected_refusal}, got {refused!r}"
    )

    cluster = _wait_cluster_status(ctx, cluster_id, "available", timeout_s=300)
    assert cluster["BackupRetentionPeriod"] in written, (
        f"final BackupRetentionPeriod {cluster['BackupRetentionPeriod']!r} is not a successful "
        f"writer's value {written!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _race_two(fn_a, fn_b) -> tuple[dict, dict]:
    """Fire fn_a and fn_b as close to simultaneously as possible using a barrier; return
    (result_a, result_b), each {"ok": True, "value": ...} or {"ok": False, "code": ..., "message": ...}."""
    barrier = threading.Barrier(2)

    def _wrap(fn):
        def _inner():
            barrier.wait()
            try:
                return {"ok": True, "value": fn(), "code": None, "message": None}
            except Exception as exc:  # noqa: BLE001 - classify below
                response = getattr(exc, "response", None)
                if response is not None:
                    return {
                        "ok": False,
                        "value": None,
                        "code": response.get("Error", {}).get("Code"),
                        "message": response.get("Error", {}).get("Message"),
                    }
                raise

        return _inner

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_wrap(fn_a))
        fut_b = pool.submit(_wrap(fn_b))
        return fut_a.result(), fut_b.result()


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=15) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status and not last.get("PendingModifiedValues"):
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
