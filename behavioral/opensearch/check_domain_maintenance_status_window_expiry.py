"""domain-maintenance-status-window-expiry."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "domain-maintenance-status-window-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A RESTART_SEARCH_PROCESS maintenance action reaches Status SUCCESS through
    GetDomainMaintenanceStatus with no further client-driven step, and the finished action is
    listed by ListDomainMaintenances with that status."""
    client = ctx.client("opensearch")
    domain_name = _create_minimal_domain(ctx)
    # A 3-node t3.small.search domain takes about 15-20 minutes to reach Active.
    _wait_domain_active(ctx, domain_name, timeout_s=1800.0)

    # The action needs a data node id from DescribeDomainNodes; the maintenance service refuses a
    # listed id as invalid until its node registry catches up, minutes after the domain is Active.
    maintenance_id = None
    deadline = time.monotonic() + _bounded(ctx, 1500.0)
    while maintenance_id is None:
        try:
            nodes = client.describe_domain_nodes(DomainName=domain_name).get("DomainNodesStatusList", [])
            node_id = next((n["NodeId"] for n in nodes if n.get("NodeId")), None)
            if node_id is not None:
                maintenance_id = client.start_domain_maintenance(
                    DomainName=domain_name, Action="RESTART_SEARCH_PROCESS", NodeId=node_id
                )["MaintenanceId"]
                break
        except ClientError as err:
            error = err.response["Error"]
            # StartDomainMaintenance has a low per-account rate limit, so a throttled call is retried.
            if error["Code"] not in ("DependencyFailureException", "ThrottlingException") and (
                error["Code"], error.get("Message")) != ("ResourceNotFoundException", _NODE_ID_INVALID):
                raise
        assert time.monotonic() < deadline, (
            f"StartDomainMaintenance never accepted a node of {domain_name}: no data node listed, "
            f"or every listed node id refused as {_NODE_ID_INVALID!r}"
        )
        # StartDomainMaintenance's low rate limit spaces the attempts 5 s apart.
        time.sleep(5.0)

    final = None
    deadline = time.monotonic() + _bounded(ctx, 1500.0)
    while time.monotonic() < deadline:
        status = client.get_domain_maintenance_status(
            DomainName=domain_name, MaintenanceId=maintenance_id
        )
        if status.get("Status") in _TERMINAL:
            final = status
            break
        time.sleep(5.0)
    assert final is not None, (
        "maintenance action never reached a terminal Status within its execution window, "
        "with no additional client-driven step issued"
    )
    # AWS reports a finished action as SUCCESS, a value outside the modelled MaintenanceStatus enum.
    assert final["Status"] == "SUCCESS", f"RESTART_SEARCH_PROCESS maintenance ended in {final['Status']}"

    recent = client.list_domain_maintenances(DomainName=domain_name).get("DomainMaintenances", [])
    match = next((m for m in recent if m["MaintenanceId"] == maintenance_id), None)
    assert match is not None, "completed maintenance action is missing from ListDomainMaintenances' recent view"
    assert match["Status"] == "SUCCESS", match


_NODE_ID_INVALID = "The requested node ID is invalid"
_TERMINAL = {"SUCCESS", "COMPLETED", "FAILED", "TIMED_OUT"}


def _bounded(ctx, wait_s: float) -> float:
    """wait_s, capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return wait_s if left is None else min(wait_s, max(0.0, left - 60.0))


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _domain_access_policy(ctx, domain_name: str) -> str:
    account_id = _account_id(ctx)
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "es:*",
                    "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
                }
            ],
        }
    )


def _create_minimal_domain(ctx, engine_version: str | None = None, auto_tune_enabled: bool = False) -> str:
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-osm-")
    kwargs = {
        "DomainName": name,
        # StartDomainMaintenance fails with DisabledOperationException ("Operation disabled for
        # domains with less than three nodes") below 3 data nodes.
        "ClusterConfig": {"InstanceType": "t3.small.search", "InstanceCount": 3},
        "EBSOptions": {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        "AccessPolicies": _domain_access_policy(ctx, name),
    }
    if engine_version:
        kwargs["EngineVersion"] = engine_version
    if auto_tune_enabled:
        kwargs["AutoTuneOptions"] = {"DesiredState": "ENABLED"}
    client.create_domain(**kwargs)
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    return name


def _wait_domain_active(ctx, domain_name: str, timeout_s: float = 1800.0, interval_s: float = 30.0) -> dict:
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        if not status.get("Processing", True):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not reach an idle (Processing=False) state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
