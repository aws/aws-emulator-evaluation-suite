"""create-cluster-with-optional-config-persists."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-with-optional-config-persists"
GROUP = "state"
SERVICES = ["docdb-elastic"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster honors optional backupRetentionPeriod, preferredBackupWindow,
    preferredMaintenanceWindow and shardInstanceCount: once ACTIVE, GetCluster echoes the
    requested values (maintenance-window day in title case), not service defaults."""
    docdb = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-docdbe-opt-")
    password = _admin_password(ctx)

    created = docdb.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName="sim2realadmin",
        adminUserPassword=password,
        shardCapacity=2,
        shardCount=1,
        shardInstanceCount=2,
        backupRetentionPeriod=3,
        preferredBackupWindow="04:00-04:30",
        preferredMaintenanceWindow="mon:05:00-mon:05:30",
        tags={"sim2real-check": CHECK},
    )["cluster"]
    arn = created["clusterArn"]
    _register_cluster_cleanup(ctx, arn)

    active = _wait_for_cluster_status(ctx, arn, {"ACTIVE"})
    assert active["shardInstanceCount"] == 2, active.get("shardInstanceCount")
    assert active["backupRetentionPeriod"] == 3, active.get("backupRetentionPeriod")
    assert active["preferredBackupWindow"] == "04:00-04:30", active.get("preferredBackupWindow")
    # real AWS normalizes the day-of-week abbreviation to title case on echo,
    # regardless of the case requested at creation (measured: "mon" in -> "Mon" out).
    assert active["preferredMaintenanceWindow"] == "Mon:05:00-Mon:05:30", active.get(
        "preferredMaintenanceWindow"
    )
    # shards is one entry per SHARD (not per replica instance): shardCount stays 1.
    assert len(active.get("shards", [])) == 1, active.get("shards")


# ===== helpers =====
def _admin_password(ctx):
    suffix = re.sub(r"[^A-Za-z0-9]", "", ctx.unique_name("x"))[:12]
    return f"S1mparityPw{suffix}"


_TRANSIENT_STATUSES = {
    "CREATING", "STARTING", "STOPPING", "UPDATING", "DELETING",
    "MERGING", "MODIFYING", "SPLITTING", "COPYING", "MAINTENANCE",
}


def _wait_for_cluster_status(ctx, arn, targets, timeout_s=1800.0, interval_s=15.0):
    docdb = ctx.client("docdb-elastic")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = docdb.get_cluster(clusterArn=arn)["cluster"]
        if last["status"] in targets:
            return last
        if last["status"] not in _TRANSIENT_STATUSES:
            raise AssertionError(
                f"cluster {arn} reached unexpected terminal status {last['status']!r} "
                f"while waiting for {targets}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {arn} did not reach {targets} within {timeout_s}s "
        f"(last status={last['status'] if last else None})"
    )


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
