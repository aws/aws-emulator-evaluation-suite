"""dry-run-progress-ttl-expiration-requires-retrigger."""
from __future__ import annotations

import random
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

CHECK = "dry-run-progress-ttl-expiration-requires-retrigger"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly triggered Verbose dry run's DryRunId is queryable and reaches "succeeded", while a
    never-triggered DryRunId fails ResourceNotFoundException "No Dry Run found ...".
    """
    client = ctx.client("opensearch")
    domain_name, status = _create_minimal_domain(ctx)
    current_type = status["ClusterConfig"]["InstanceType"]
    other_type = "t3.medium.search" if current_type != "t3.medium.search" else "t3.small.search"

    # DryRunMode="Verbose" is required to get a DryRunProgressStatus/DryRunId back at all --
    # the default "Basic" mode returns only DryRunResults with no queryable id.
    dry_run = client.update_domain_config(
        DomainName=domain_name,
        ClusterConfig={"InstanceType": other_type},
        DryRun=True,
        DryRunMode="Verbose",
    )
    dry_run_id = dry_run["DryRunProgressStatus"]["DryRunId"]

    # Positive: the real, just-triggered DryRunId is queryable and reports its own id back.
    # The Verbose analysis is asynchronous, so wait it out with a bounded poll rather than
    # assuming the very first read is already terminal.
    # The DryRunId TTL is undocumented, so expiry itself is not awaited.
    real_progress = _poll_until_terminal(client, domain_name, dry_run_id, timeout_s=280.0)
    assert real_progress["DryRunProgressStatus"]["DryRunId"] == dry_run_id, (
        f"expected the just-triggered DryRunId {dry_run_id!r} echoed back, "
        f"got {real_progress['DryRunProgressStatus'].get('DryRunId')!r}"
    )
    # DryRunStatus has no documented enum; AWS reports lowercase "succeeded"/"failed".
    assert real_progress["DryRunProgressStatus"]["DryRunStatus"] == "succeeded", (
        f"expected the config-validation dry run to reach 'succeeded', got {real_progress!r}"
    )

    # Negative: a DryRunId that was never produced by a real dry run is not silently served
    # cached/synthetic progress.
    fake_dry_run_id = str(uuid.uuid4())
    code, message = _error(
        lambda: client.describe_dry_run_progress(DomainName=domain_name, DryRunId=fake_dry_run_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-triggered DryRunId, got {code!r}"
    )
    expected = f"No Dry Run found for the provided DryRunId: {fake_dry_run_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_until_terminal(client, domain_name, dry_run_id, *, timeout_s):
    # AWS reports lowercase "pending", unlike the docs' example casing; compare case-insensitively.
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.describe_dry_run_progress(DomainName=domain_name, DryRunId=dry_run_id)
        if last["DryRunProgressStatus"]["DryRunStatus"].lower() not in ("pending", "in_progress"):
            return last
        time.sleep(2)
    raise AssertionError(f"dry run {dry_run_id} never left pending/in_progress within {timeout_s}s: {last!r}")


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _create_minimal_domain(ctx):
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-osd-")
    kwargs = dict(
        DomainName=name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    for attempt in range(12):
        try:
            client.create_domain(**kwargs)
            break
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled on CreateDomain after 12 attempts")
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    deadline = time.monotonic() + 1800
    status = None
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return name, status
        time.sleep(2)
    raise AssertionError(f"domain {name} did not become active within budget: {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
