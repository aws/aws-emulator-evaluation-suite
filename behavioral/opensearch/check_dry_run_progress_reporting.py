"""dry-run-progress-reporting."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dry-run-progress-reporting"
GROUP = 'domain'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _create_domain(ctx, osc, domain_name) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    for _attempt in range(12):
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    return resp["DomainStatus"]


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """Bounded poll until Processing=False and Created=True; the same budget applies on
    every target, and a domain that never settles raises."""
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name} never became Active within {budget}s",
    )


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=8.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn) -> "tuple[str, str]":
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDomainConfig(DryRun=True) creates a dry-run validation whose progress
    DescribeDryRunProgress tracks by DryRunId; an unknown DryRunId 404s."""
    osc = ctx.client("opensearch")
    time.sleep(random.uniform(0, 20.0))
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)
    _wait_domain_active(ctx, osc, domain)

    dry_run_resp = osc.update_domain_config(
        DomainName=domain,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 3},
        DryRun=True,
        DryRunMode="Verbose",
    )
    dry_run_id = dry_run_resp.get("DryRunProgressStatus", {}).get("DryRunId")
    assert dry_run_id, f"expected a DryRunId in the dry-run response, got {dry_run_resp}"

    settled = _poll_until(
        lambda: osc.describe_dry_run_progress(DomainName=domain, DryRunId=dry_run_id),
        lambda r: r.get("DryRunProgressStatus", {}).get("DryRunStatus")
        not in ("PENDING", "IN_PROGRESS", "Processing"),
        timeout_s=300,
        interval_s=8.0,
        description=f"dry run {dry_run_id} settled",
    )
    assert settled["DryRunProgressStatus"]["DryRunId"] == dry_run_id, (
        f"expected the settled progress to echo back DryRunId {dry_run_id}, "
        f"got {settled['DryRunProgressStatus'].get('DryRunId')!r}"
    )
    assert "DryRunResults" in settled, f"expected DryRunResults once settled, got {settled}"

    # The live config must not have actually changed as a result of the dry run.
    live = osc.describe_domain_config(DomainName=domain)["DomainConfig"]
    assert live["ClusterConfig"]["Options"]["InstanceCount"] == 1, (
        f"DryRun must not mutate live config, but InstanceCount is now "
        f"{live['ClusterConfig']['Options']['InstanceCount']}"
    )

    # Overly-permissive boundary: an unknown DryRunId must 404.
    code, message = _error(
        lambda: osc.describe_dry_run_progress(
            DomainName=domain, DryRunId="00000000-0000-0000-0000-000000000000"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "No Dry Run found for the provided DryRunId: 00000000-0000-0000-0000-000000000000"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
