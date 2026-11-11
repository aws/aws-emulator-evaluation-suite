"""create-cluster-invalid-shard-capacity-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-invalid-shard-capacity-rejected"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster rejects a shardCapacity outside the allowed {2,4,8,16,32,64} set, never
    provisions a cluster under that name, while a valid shardCapacity still succeeds (control)."""
    docdb = ctx.client("docdb-elastic")
    bad_name = ctx.unique_name("sim2real-docdbe-bad-")
    password = _admin_password(ctx)

    code, message = _error(
        lambda: docdb.create_cluster(
            clusterName=bad_name,
            authType="PLAIN_TEXT",
            adminUserName="sim2realadmin",
            adminUserPassword=password,
            shardCapacity=3,  # not one of the allowed values
            shardCount=1,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid Input - '3'. ShardCapacity must be a power of 2 within [2, 64].", (
        f"unexpected message: {message!r}"
    )

    # Effect absent: the rejected clusterName must never have been provisioned.
    assert not _cluster_name_exists(ctx, bad_name.lower()), (
        f"cluster {bad_name!r} exists despite a rejected CreateCluster call"
    )

    # Positive control: an otherwise-identical request with a valid shardCapacity succeeds.
    good_name = ctx.unique_name("sim2real-docdbe-good-")
    created = docdb.create_cluster(
        clusterName=good_name,
        authType="PLAIN_TEXT",
        adminUserName="sim2realadmin",
        adminUserPassword=password,
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK},
    )["cluster"]
    _register_cluster_cleanup(ctx, created["clusterArn"])
    assert created["shardCapacity"] == 2, f"expected shardCapacity 2, got {created['shardCapacity']!r}"

    # Terminal read is independent of the mutating call: poll GetCluster (not CreateCluster's
    # own echoed response) until the accepted shardCapacity actually reaches ACTIVE.
    active = _wait_for_status(docdb, created["clusterArn"], {"ACTIVE"})
    assert active["shardCapacity"] == 2, f"expected shardCapacity 2, got {active['shardCapacity']!r}"
    assert active["status"] == "ACTIVE", active["status"]


# ===== helpers =====
def _admin_password(ctx):
    suffix = re.sub(r"[^A-Za-z0-9]", "", ctx.unique_name("x"))[:12]
    return f"S1mparityPw{suffix}"


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting what real AWS refuses must not be reported as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _cluster_name_exists(ctx, name_lower, max_pages=20):
    docdb = ctx.client("docdb-elastic")
    token = None
    for _ in range(max_pages):
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = docdb.list_clusters(**kwargs)
        for cluster in resp.get("clusters", []):
            if cluster.get("clusterName") == name_lower:
                return True
        token = resp.get("nextToken")
        if not token:
            break
    return False


def _wait_for_status(docdb, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = docdb.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_status = cluster["status"]
        if last_status in target_statuses:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={last_status}")


def _register_cluster_cleanup(ctx, arn):
    def _cleanup():
        docdb = ctx.client("docdb-elastic")
        # fits the suite's 900 s cleanup budget
        deadline = time.monotonic() + 840.0
        while time.monotonic() < deadline:
            try:
                docdb.delete_cluster(clusterArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code == "ConflictException":
                    try:
                        status = docdb.get_cluster(clusterArn=arn)["cluster"]["status"]
                    except ClientError as err:
                        if err.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
                        return
                    if status == "STOPPED":
                        try:
                            docdb.start_cluster(clusterArn=arn)
                        except ClientError as err:
                            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                                raise
                    time.sleep(2.0)
                    continue
                raise
        raise AssertionError(f"cluster {arn} still refused DeleteCluster after 840 s")

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
