"""blue-green-deployment-lifecycle."""
from __future__ import annotations

import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "blue-green-deployment-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]

_ADMIN_PW = "S2r" + secrets.token_urlsafe(18)

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A blue/green deployment of an Aurora MySQL cluster (ROW binlog, writer in-sync with its
    cluster parameter group) reaches AVAILABLE, and SwitchoverBlueGreenDeployment takes it to
    SWITCHOVER_COMPLETED."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    # Not `DefaultOnly=True`: the default Aurora MySQL version is often a just-promoted major with
    # slower provisioning, so the check picks the latest minor of the previous, established major.
    engine_version = _pick_established_engine_version(rds, "aurora-mysql")

    # Aurora MySQL Blue/Green Deployments require ROW-format binary logging on the source
    # (SourceClusterNotSupportedFault otherwise), set by a custom cluster parameter group at
    # cluster create; the writer still needs the explicit reboot below to be in-sync.
    family = rds.describe_db_engine_versions(
        Engine="aurora-mysql", EngineVersion=engine_version
    )["DBEngineVersions"][0]["DBParameterGroupFamily"]
    cluster_param_group = ctx.unique_name("sim2real-behav-cpg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=cluster_param_group,
        DBParameterGroupFamily=family,
        Description="sim2real behavioral check: enable ROW-format binlog for Blue/Green",
        Tags=_MANAGED_TAGS,
    )
    rds.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=cluster_param_group,
        Parameters=[{"ParameterName": "binlog_format", "ParameterValue": "ROW", "ApplyMethod": "pending-reboot"}],
    )
    ctx.on_cleanup(lambda: _delete_when_released(
        lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=cluster_param_group),
        ("InvalidDBParameterGroupState", "InvalidDBParameterGroupStateFault"),
        ("DBParameterGroupNotFound", "DBParameterGroupNotFoundFault"),
    ))
    # One teardown for the whole topology (registered after the parameter group, so it runs
    # before it): the deployment, the green side, the source and, after a switchover, the
    # demoted "-old1" side, each deleted and waited out.
    topology: dict[str, Any] = {"bg_id": None, "clusters": [], "instances": []}
    ctx.on_cleanup(lambda: _teardown_topology(rds, topology))

    source_cluster_id = ctx.unique_name("sim2real-behav-src-")
    rds.create_db_cluster(
        DBClusterIdentifier=source_cluster_id,
        Engine="aurora-mysql",
        EngineVersion=engine_version,
        MasterUsername="simadmin",
        MasterUserPassword=_ADMIN_PW,
        DBSubnetGroupName=subnet_group,
        DBClusterParameterGroupName=cluster_param_group,
        # Serverless v2: a fixed-capacity writer takes 400-600 s to boot, too much of the budget
        # the green environment's own boot and the switchover also need.
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        Tags=_MANAGED_TAGS,
    )
    topology["clusters"] += [source_cluster_id, f"{source_cluster_id}-old1"]

    source_instance_id = ctx.unique_name("sim2real-behav-srci-")

    rds.create_db_instance(
        DBInstanceIdentifier=source_instance_id,
        DBClusterIdentifier=source_cluster_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    topology["instances"] += [source_instance_id, f"{source_instance_id}-old1"]
    # A Serverless v2 writer takes about 430-450 s to report "available" on AWS.
    _wait_instance_status(ctx, source_instance_id, {"available"}, timeout_s=600.0, interval_s=6.0)
    # The cluster reports "available" no later than its writer does, so one describe is enough
    # to fetch the ARN.
    source_cluster = rds.describe_db_clusters(DBClusterIdentifier=source_cluster_id)["DBClusters"][0]
    assert source_cluster["Status"] == "available", f"expected source cluster available, got {source_cluster['Status']!r}"
    source_arn = source_cluster["DBClusterArn"]

    # A cluster parameter group attached at create leaves the writer "pending-reboot" until it is
    # rebooted, and CreateBlueGreenDeployment refuses a writer that is not "in-sync"
    # (SourceClusterNotSupportedFault).
    writer = next(m for m in source_cluster["DBClusterMembers"] if m["IsClusterWriter"])
    if writer["DBClusterParameterGroupStatus"] != "in-sync":
        rds.reboot_db_instance(DBInstanceIdentifier=source_instance_id)
        _wait_instance_status(ctx, source_instance_id, {"available"}, timeout_s=300.0, interval_s=6.0)
        source_cluster = _wait_cluster_writer_param_in_sync(ctx, source_cluster_id, timeout_s=180.0)
        writer = next(m for m in source_cluster["DBClusterMembers"] if m["IsClusterWriter"])
    assert writer["DBClusterParameterGroupStatus"] == "in-sync", (
        f"expected writer {writer['DBInstanceIdentifier']!r} cluster-parameter-group status "
        f"in-sync, got {writer['DBClusterParameterGroupStatus']!r}"
    )

    bg_name = ctx.unique_name("sim2real-behav-bg-")
    resp = rds.create_blue_green_deployment(
        BlueGreenDeploymentName=bg_name, Source=source_arn, Tags=_MANAGED_TAGS
    )
    bg_id = resp["BlueGreenDeployment"]["BlueGreenDeploymentIdentifier"]

    topology["bg_id"] = bg_id

    # 1800 s: the green environment's initial read-replica sync can keep it PROVISIONING past
    # 900 s, far longer than the "typically under a minute" the RDS docs give for the switchover.
    bg = _wait_bg_status(ctx, bg_id, {"AVAILABLE"}, timeout_s=1800.0, interval_s=10.0)
    for member in bg["SwitchoverDetails"]:
        kind, name = member["TargetMember"].split(":")[-2:]
        topology["clusters" if kind == "cluster" else "instances"].append(name)

    # A switchover whose guardrails do not clear in time is rolled back (members
    # SWITCHOVER_FAILED, deployment AVAILABLE again); that outcome is retried once.
    for _attempt in range(2):
        rds.switchover_blue_green_deployment(BlueGreenDeploymentIdentifier=bg_id, SwitchoverTimeout=900)
        bg = _wait_bg_status(
            ctx, bg_id, {"SWITCHOVER_COMPLETED", "SWITCHOVER_FAILED", "AVAILABLE"}, timeout_s=1200.0, interval_s=15.0
        )
        # The deployment reports AVAILABLE for a moment after the call, before SWITCHOVER_IN_PROGRESS.
        if bg["Status"] == "AVAILABLE" and not any(
            m.get("Status") == "SWITCHOVER_FAILED" for m in bg.get("SwitchoverDetails", [])
        ):
            bg = _wait_bg_status(ctx, bg_id, {"SWITCHOVER_COMPLETED", "SWITCHOVER_FAILED"}, timeout_s=1200.0, interval_s=15.0)
        if bg["Status"] == "SWITCHOVER_COMPLETED":
            break
        _wait_bg_status(ctx, bg_id, {"AVAILABLE"}, timeout_s=600.0, interval_s=15.0)
    assert bg["Status"] == "SWITCHOVER_COMPLETED", (
        f"expected blue/green deployment {bg_id!r} to reach SWITCHOVER_COMPLETED, "
        f"got {bg['Status']!r}"
    )


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=600.0, interval_s=15.0):
    """Delete a resource, retrying while a deleted cluster still holds it; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _teardown_topology(rds, topology, timeout_s=1500.0) -> None:
    """Delete the blue/green deployment, then every instance, then every cluster, waiting for
    each tier to be gone; raise naming whatever is still there at the deadline."""
    deadline = time.monotonic() + timeout_s
    bg_id = topology["bg_id"]
    if bg_id:
        try:
            bg = rds.describe_blue_green_deployments(BlueGreenDeploymentIdentifier=bg_id)["BlueGreenDeployments"][0]
            # DeleteTarget is refused once a switchover completed; the promoted side then
            # carries the source's names and is deleted below like any other member.
            rds.delete_blue_green_deployment(
                BlueGreenDeploymentIdentifier=bg_id, DeleteTarget=bg["Status"] != "SWITCHOVER_COMPLETED"
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "BlueGreenDeploymentNotFoundFault":
                raise
        while time.monotonic() < deadline:
            try:
                rds.describe_blue_green_deployments(BlueGreenDeploymentIdentifier=bg_id)
            except ClientError as e:
                if e.response["Error"]["Code"] == "BlueGreenDeploymentNotFoundFault":
                    break
                raise
            time.sleep(15)

    def _drain(names, describe, delete, not_found, busy):
        left = list(dict.fromkeys(names))
        while left:
            for name in list(left):
                try:
                    describe(name)
                except ClientError as e:
                    if e.response["Error"]["Code"] == not_found:
                        left.remove(name)
                        continue
                    raise
                try:
                    delete(name)
                except ClientError as e:
                    if e.response["Error"]["Code"] not in (not_found, *busy):
                        raise
            if left:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"still present {timeout_s}s into teardown: {left}")
                time.sleep(20)

    _drain(
        topology["instances"],
        lambda n: rds.describe_db_instances(DBInstanceIdentifier=n),
        lambda n: rds.delete_db_instance(DBInstanceIdentifier=n, SkipFinalSnapshot=True),
        "DBInstanceNotFound",
        ("InvalidDBInstanceState", "InvalidDBInstanceStateFault"),
    )
    _drain(
        topology["clusters"],
        lambda n: rds.describe_db_clusters(DBClusterIdentifier=n),
        lambda n: rds.delete_db_cluster(DBClusterIdentifier=n, SkipFinalSnapshot=True),
        "DBClusterNotFoundFault",
        ("InvalidDBClusterStateFault",),
    )


def _pick_established_engine_version(rds, engine: str) -> str:
    """The latest minor version of the second-newest major version of ``engine``; for Aurora
    MySQL (``"8.0.mysql_aurora.3.05.2"``) the major is the number after ``mysql_aurora.``, for
    other engines the leading number."""
    versions = [
        v for v in rds.describe_db_engine_versions(Engine=engine)["DBEngineVersions"]
        if v.get("Status", "available") == "available"
    ]

    def _major(v: str) -> int:
        marker = "mysql_aurora."
        idx = v.find(marker)
        if idx != -1:
            return int(v[idx + len(marker):].split(".")[0])
        return int(v.split(".")[0])

    def _ver_key(v: str):
        return tuple(int(p) if p.isdigit() else p for p in v.split("."))

    majors = sorted({_major(v["EngineVersion"]) for v in versions}, reverse=True)
    target_major = majors[1] if len(majors) > 1 else majors[0]
    candidates = [v["EngineVersion"] for v in versions if _major(v["EngineVersion"]) == target_major]
    assert candidates, f"no {engine} engine versions found for major version {target_major}"
    return sorted(candidates, key=_ver_key)[-1]


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_subnet_group(ctx) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=ctx.network().subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_when_released(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
        ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
        ("DBSubnetGroupNotFoundFault",),
    ))
    return name


def _wait_instance_status(ctx, instance_id: str, statuses: set[str], timeout_s: float = 600.0, interval_s: float = 10.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_bg_status(ctx, bg_id: str, statuses: set[str], timeout_s: float = 600.0, interval_s: float = 15.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_blue_green_deployments(BlueGreenDeploymentIdentifier=bg_id)["BlueGreenDeployments"][0]

    return _poll_until(probe, lambda b: b["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_cluster_writer_param_in_sync(ctx, cluster_id: str, timeout_s: float = 180.0, interval_s: float = 6.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    def writer_in_sync(cluster: dict[str, Any]) -> bool:
        writer = next(m for m in cluster["DBClusterMembers"] if m["IsClusterWriter"])
        return writer["DBClusterParameterGroupStatus"] == "in-sync"

    return _poll_until(probe, writer_in_sync, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
