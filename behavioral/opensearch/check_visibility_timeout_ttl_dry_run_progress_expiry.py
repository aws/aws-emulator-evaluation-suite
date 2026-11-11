"""visibility-timeout-ttl-dry-run-progress-expiry."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "visibility-timeout-ttl-dry-run-progress-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDryRunProgress serves a dry run right after it completes, but after a real
    UpdateDomainConfig overwrites it the stale DryRunId fails ResourceNotFoundException.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-configuration-changes.html
    """
    opensearch = ctx.client("opensearch")
    name = _domain_name(ctx, "dryrun")
    opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
    )
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=name))
    _wait_domain_active(ctx, name)

    dry_run_resp = opensearch.update_domain_config(
        DomainName=name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 2},
        DryRun=True,
        DryRunMode="Verbose",
    )
    dry_run_id = dry_run_resp["DryRunProgressStatus"]["DryRunId"]
    assert len(dry_run_id) == 36, f"expected a UUID-shaped DryRunId, got {dry_run_id!r}"

    terminal_status = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        progress = opensearch.describe_dry_run_progress(DomainName=name, DryRunId=dry_run_id)
        status = progress["DryRunProgressStatus"]
        assert status["DryRunId"] == dry_run_id, (
            f"expected DescribeDryRunProgress to echo {dry_run_id!r}, got {status['DryRunId']!r}"
        )
        if status["DryRunStatus"] in ("succeeded", "failed"):
            terminal_status = status["DryRunStatus"]
            break
        time.sleep(5)
    assert terminal_status in ("succeeded", "failed"), "dry run never reached a terminal status"

    # A real (non-dry-run) config change overwrites the pending dry run.
    opensearch.update_domain_config(
        DomainName=name,
        EBSOptions={"EBSEnabled": True, "VolumeSize": 11, "VolumeType": "gp3"},
    )

    code, message = _poll_until_rejected(
        lambda: opensearch.describe_dry_run_progress(DomainName=name, DryRunId=dry_run_id),
        timeout_s=600.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"No Dry Run found for the provided DryRunId: {dry_run_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

def _domain_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real{tag}").lower()
    name = "".join(ch for ch in raw if ch.isalnum() or ch == "-")[:28].rstrip("-")
    return name or f"sim2real{tag}0"


def _wait_domain_active(ctx, name: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> dict:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Created") and not last.get("Processing"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s (last={last})")


def _poll_until_rejected(fn, *, timeout_s: float, interval_s: float = 5.0):
    """Call fn() until it raises; return that botocore Error (code, message). Raises if it keeps
    succeeding past the deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call still succeeded after {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
