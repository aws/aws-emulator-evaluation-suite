"""domain-maintenance-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-maintenance-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]

# GetDomainMaintenanceStatus reports a completed action as Status="SUCCESS", not the "COMPLETED"
# the model's MaintenanceStatus enum lists; COMPLETED stays a terminal status, and the completion
# assertion below pins SUCCESS.
_TERMINAL_STATUSES = {"SUCCESS", "COMPLETED", "FAILED", "TIMED_OUT"}


def _call_with_backoff(fn, *args, retries: int = 6, base_delay: float = 3.0, **kwargs):
    """Retry on ThrottlingException with exponential backoff.

    Domain-creating checks can exceed the account's request rate for Describe*/List* calls;
    an explicit backoff keeps that wait visible and bounded.
    """
    last_err = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ThrottlingException":
                raise
            last_err = err
            if attempt < retries - 1:
                time.sleep(base_delay * (2 ** attempt))
    raise last_err


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartDomainMaintenance RESTART_SEARCH_PROCESS on a listed node reports that action and node, is listed
    by ListDomainMaintenances before and after it runs, and reaches Status SUCCESS."""
    domain_name = _start_domain_creation(ctx)
    osv = ctx.client("opensearch")

    # Node discovery and the maintenance start are polled in one bounded loop. For several minutes
    # after the domain is Active, StartDomainMaintenance answers ResourceNotFoundException "The
    # requested node ID is invalid" for a listed node; the same id is then accepted, and a
    # search-process restart on t3.small runs for about 18 minutes. StartDomainMaintenance is also
    # tightly rate-limited, so attempts are 30 s apart. The 1900 s start window and the 1500 s
    # terminal poll together fit the suite's 3600 s budget.
    node_id, started = _wait_and_start_maintenance(osv, domain_name, timeout_s=1900.0, interval_s=30.0)
    maintenance_id = started["MaintenanceId"]

    status = _call_with_backoff(
        osv.get_domain_maintenance_status,
        DomainName=domain_name, MaintenanceId=maintenance_id,
    )
    assert status["Action"] == "RESTART_SEARCH_PROCESS", f"expected RESTART_SEARCH_PROCESS, got {status['Action']!r}"
    assert status["NodeId"] == node_id, f"maintenance status is for node {status['NodeId']!r}, expected {node_id!r}"

    listed_before = _list_maintenance_ids(osv, domain_name)
    assert maintenance_id in listed_before, "maintenance action missing from ListDomainMaintenances"

    final_status = _wait_maintenance_terminal(osv, domain_name, maintenance_id, timeout_s=1500.0, interval_s=30.0)
    assert final_status in _TERMINAL_STATUSES, f"maintenance did not reach a terminal status: {final_status!r}"
    assert final_status == "SUCCESS", f"expected the maintenance action to SUCCEED, got {final_status!r}"

    listed_after = _list_maintenance_ids(osv, domain_name)
    assert maintenance_id in listed_after, "maintenance action missing from ListDomainMaintenances after completion"


# ===== helpers =====

def _short_domain_name(ctx, tag: str) -> str:
    # OpenSearch domain names are capped at 28 chars and must match [a-z][a-z0-9\-]+.
    # "sim2real-dm-" + 12 hex is 24, so the sim2real- prefix survives intact.
    raw = ctx.unique_name(f"sim2real-{tag}-").lower()
    if len(raw) > 28:
        raw = raw[-28:]
    if not raw[0].isalpha():
        raw = "d" + raw[1:]
    return raw


def _start_domain_creation(ctx) -> str:
    """Start domain creation WITHOUT waiting for it to become Active, which can take 10+ minutes;
    the combined node-discovery/maintenance-start loop absorbs the remaining provisioning time."""
    osv = ctx.client("opensearch")
    domain_name = _short_domain_name(ctx, "dm")
    _call_with_backoff(
        osv.create_domain,
        DomainName=domain_name,
        # A pinned engine version: the default (latest) release can take noticeably longer to
        # provision, and creation plus the maintenance action must fit the check's time budget.
        EngineVersion="OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            # RESTART_SEARCH_PROCESS fails with DisabledOperationException ("Operation disabled
            # for domains with less than three nodes") below 3 data nodes.
            "InstanceCount": 3,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": "domain-maintenance-lifecycle"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(osv, domain_name))
    return domain_name


def _wait_and_start_maintenance(
    osv, domain_name: str, timeout_s: float = 1400.0, interval_s: float = 10.0
) -> tuple[str, dict]:
    """Poll DescribeDomainNodes for a node id and attempt StartDomainMaintenance in the SAME
    bounded loop, retrying on the transient errors either call can throw while the domain is
    still provisioning / the maintenance node registry is catching up behind it:
    ResourceNotFoundException (node id not yet recognized by the maintenance subsystem),
    ValidationException (domain not found yet, or not yet in a state that supports
    maintenance), and DependencyFailureException ("The node information is not available
    now, please try again later" -- DescribeDomainNodes' own backing node registry hasn't
    caught up yet, distinct from the domain's own Created/Processing state). Any other error
    is fatal.
    """
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            nodes = _call_with_backoff(
                osv.describe_domain_nodes, DomainName=domain_name
            ).get("DomainNodesStatusList", [])
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") not in (
                "ResourceNotFoundException", "ValidationException", "DependencyFailureException",
            ):
                raise
            last_err = err
            time.sleep(interval_s)
            continue
        if not nodes:
            time.sleep(interval_s)
            continue
        node_id = nodes[0]["NodeId"]
        try:
            started = _call_with_backoff(
                osv.start_domain_maintenance,
                DomainName=domain_name, Action="RESTART_SEARCH_PROCESS", NodeId=node_id,
            )
            return node_id, started
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") not in (
                "ResourceNotFoundException", "ValidationException",
            ):
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err or AssertionError(
        f"domain {domain_name} never became ready for maintenance within {timeout_s}s"
    )


def _list_maintenance_ids(osv, domain_name: str) -> set[str]:
    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"DomainName": domain_name}
        if token:
            kwargs["NextToken"] = token
        resp = _call_with_backoff(osv.list_domain_maintenances, **kwargs)
        for m in resp.get("DomainMaintenances", []):
            ids.add(m["MaintenanceId"])
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _wait_maintenance_terminal(osv, domain_name: str, maintenance_id: str, timeout_s: float = 300.0, interval_s: float = 15.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _call_with_backoff(
            osv.get_domain_maintenance_status,
            DomainName=domain_name, MaintenanceId=maintenance_id,
        )["Status"]
        if last in _TERMINAL_STATUSES:
            return last
        time.sleep(interval_s)
    return last


def _safe_delete_domain(osv, domain_name: str) -> None:
    try:
        osv.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
