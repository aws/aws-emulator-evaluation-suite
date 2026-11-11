"""disabled-operation-gating-across-readonly-apis."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "disabled-operation-gating-across-readonly-apis"
GROUP = "server-side"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RESTART_SEARCH_PROCESS on a 1-data-node domain fails ResourceNotFoundException and records
    nothing; reads of never-created resources fail, not fabricate records, and ListVpcEndpoints
    is empty. At 3 data nodes the same StartDomainMaintenance succeeds and is listed.
    """
    domain_name = _domain_name(ctx, "dis")
    _create_minimal_domain(ctx, domain_name, instance_count=1)
    _wait_domain_active(ctx, domain_name)

    opensearch = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # The 3+ data node requirement is enforced via NodeId eligibility: a real Data NodeId is
    # rejected as "The requested node ID is invalid", not DisabledOperationException.
    node_id = _first_node_id(ctx, domain_name)

    code = _error_code(
        lambda: opensearch.start_domain_maintenance(
            DomainName=domain_name, Action="RESTART_SEARCH_PROCESS", NodeId=node_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"

    # Effect absent: no maintenance record was created for the rejected action.
    maintenances = opensearch.list_domain_maintenances(DomainName=domain_name)["DomainMaintenances"]
    assert maintenances == [], f"expected no maintenance records after the blocked call, got {maintenances!r}"

    # A fabricated maintenance id on this domain must be a real not-found, not a fabricated
    # default status record.
    fabricated_id = str(uuid.uuid4())
    code2 = _error_code(
        lambda: opensearch.get_domain_maintenance_status(
            DomainName=domain_name, MaintenanceId=fabricated_id
        )
    )
    assert code2 in ("ResourceNotFoundException", "DisabledOperationException"), (
        f"expected ResourceNotFoundException (or DisabledOperationException), got {code2!r}"
    )

    # A fabricated application id for DescribeDataSourceAttachment must likewise be a real
    # not-found, not an empty/default attachment. Use OUR OWN account id and region for the
    # dataSourceArn -- a foreign account id trips a materially different AccessDeniedException
    # rather than "not found" (DescribeDataSourceAttachment's modelled error set includes
    # AccessDeniedException precisely for that case).
    fabricated_app_id = uuid.uuid4().hex[:10]
    fabricated_domain_arn = (
        f"arn:aws:es:{ctx.region}:{account_id}:domain/{_domain_name(ctx, 'dis-nonexist')}"
    )
    code3 = _error_code(
        lambda: opensearch.describe_data_source_attachment(
            id=fabricated_app_id, dataSourceArn=fabricated_domain_arn
        )
    )
    assert code3 in ("ResourceNotFoundException", "ValidationException", "DisabledOperationException"), (
        f"expected ResourceNotFoundException/ValidationException/DisabledOperationException, got {code3!r}"
    )

    # DescribeDryRunProgress with no dry run ever started on this domain: a real not-found, not
    # a fabricated empty progress record.
    try:
        dry_run_resp = opensearch.describe_dry_run_progress(DomainName=domain_name)
        code4 = None
    except ClientError as exc:
        dry_run_resp = None
        code4 = exc.response["Error"]["Code"]
    assert code4 in (None, "ResourceNotFoundException", "DisabledOperationException"), (
        f"expected ResourceNotFoundException/DisabledOperationException (or a genuinely empty "
        f"record), got {code4!r}"
    )
    if code4 is None:
        # Some accounts answer 200 instead of erroring: it must not claim an in-progress or
        # completed dry run that was never requested on this domain.
        dry_run_status = (dry_run_resp or {}).get("DryRunProgressStatus", {}).get("DryRunStatus")
        assert dry_run_status not in ("PENDING", "IN_PROGRESS", "COMPLETED"), (
            f"no dry run was ever started on {domain_name}, but DescribeDryRunProgress claims "
            f"DryRunStatus={dry_run_status!r}: {dry_run_resp!r}"
        )

    # Contrast: a genuinely-empty, always-supported read on the same domain succeeds with [].
    vpc_endpoints = opensearch.list_vpc_endpoints_for_domain(DomainName=domain_name)[
        "VpcEndpointSummaryList"
    ]
    assert vpc_endpoints == [], f"expected no VPC endpoints on a fresh domain, got {vpc_endpoints!r}"

    # Positive control: scale to 3 data nodes. Node eligibility lags Processing=False, so retry
    # only on ResourceNotFoundException, within a bound.
    opensearch.update_domain_config(DomainName=domain_name, ClusterConfig={"InstanceCount": 3})
    _wait_domain_active(ctx, domain_name)

    retry = _start_maintenance_when_eligible(opensearch, domain_name, "RESTART_SEARCH_PROCESS")
    maintenance_id = retry["MaintenanceId"]
    status = opensearch.get_domain_maintenance_status(
        DomainName=domain_name, MaintenanceId=maintenance_id
    )
    assert status["Status"] in ("PENDING", "IN_PROGRESS", "COMPLETED", "FAILED", "TIMED_OUT"), (
        f"unexpected maintenance status shape: {status!r}"
    )

    # Independent read at a different operation: the accepted retry is now visible in the
    # domain's maintenance list, in contrast to the blocked call's demonstrated absence above.
    after_ids = {
        m["MaintenanceId"]
        for m in opensearch.list_domain_maintenances(DomainName=domain_name)["DomainMaintenances"]
    }
    assert maintenance_id in after_ids, (
        f"maintenance {maintenance_id} reported by StartDomainMaintenance is not visible in "
        f"ListDomainMaintenances: {after_ids!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _domain_name(ctx, tag: str) -> str:
    return f"sim2real-{tag}-{uuid.uuid4().hex[:10]}"[:28]


def _create_minimal_domain(ctx, name, *, instance_count: int = 1, instance_type: str = "t3.small.search") -> None:
    opensearch = ctx.client("opensearch")
    opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": instance_type,
            "InstanceCount": instance_count,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_domain(ctx, name))


def _delete_domain(ctx, name) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _first_node_id(ctx, name) -> str:
    opensearch = ctx.client("opensearch")
    nodes = opensearch.describe_domain_nodes(DomainName=name)["DomainNodesStatusList"]
    data_nodes = [n for n in nodes if n.get("NodeType") == "Data"] or nodes
    assert data_nodes, f"domain {name} reported no nodes"
    return data_nodes[0]["NodeId"]


def _start_maintenance_when_eligible(
    opensearch, domain_name, action, *, timeout_s: float = 600.0, interval_s: float = 20.0
):
    """Retry StartDomainMaintenance while nodes are not yet eligible (ResourceNotFoundException).

    Any other error raises immediately.
    """
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        nodes = opensearch.describe_domain_nodes(DomainName=domain_name)["DomainNodesStatusList"]
        data_nodes = [n for n in nodes if n.get("NodeType") == "Data"] or nodes
        assert data_nodes, f"domain {domain_name} reported no nodes"
        node_id = data_nodes[0]["NodeId"]
        try:
            return opensearch.start_domain_maintenance(
                DomainName=domain_name, Action=action, NodeId=node_id
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
    raise AssertionError(
        f"StartDomainMaintenance({action}) on {domain_name} never became eligible within "
        f"{timeout_s}s (last error: {last_code!r})"
    )


def _wait_domain_active(ctx, name, timeout_s: float = 1800.0, interval_s: float = 30.0):

    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active/idle within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
