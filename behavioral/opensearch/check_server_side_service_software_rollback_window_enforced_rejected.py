"""server-side-service-software-rollback-window-enforced-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-service-software-rollback-window-enforced-rejected"
GROUP = "server-side"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Outside the rollback window (a settled domain with no update in flight)
    RollbackServiceSoftwareUpdate is declined in a 200 (RollbackAvailable False, exact Description),
    ServiceSoftwareOptions stays untouched, and other domain APIs keep working (positive control)."""
    client = ctx.client("opensearch")
    domain_name = _domain_name(ctx)
    _create_domain(ctx, domain_name)
    _wait_domain_active(ctx, domain_name, timeout_s=1800)

    before_sso, rollback_resp = _rollback_once_settled(ctx, client, domain_name)
    rollback_opts = rollback_resp.get("RollbackServiceSoftwareOptions", {})
    assert rollback_opts.get("RollbackAvailable") is False, (
        f"expected the 200 to decline the rollback with RollbackAvailable=False, got {rollback_opts!r}"
    )
    assert rollback_opts.get("Description") == (
        "No previous software version available for rollback. Please contact AWS Support for "
        "assistance."
    ), f"unexpected rollback decline description: {rollback_opts.get('Description')!r}"

    after = client.describe_domain(DomainName=domain_name)["DomainStatus"]
    after_sso = after.get("ServiceSoftwareOptions", {})
    assert after_sso.get("UpdateStatus") == before_sso.get("UpdateStatus"), (
        f"UpdateStatus changed as a side effect of a rejected rollback: "
        f"{before_sso.get('UpdateStatus')!r} -> {after_sso.get('UpdateStatus')!r}"
    )
    assert after_sso.get("CurrentVersion") == before_sso.get("CurrentVersion"), (
        "CurrentVersion changed as a side effect of a rejected rollback"
    )

    # Positive control: a sibling read on the same domain still works, so the decline is
    # specific to the out-of-window rollback.
    config = client.describe_domain_config(DomainName=domain_name)["DomainConfig"]
    instance_type = config["ClusterConfig"]["Options"]["InstanceType"]
    assert instance_type == "t3.small.search", (
        f"expected sibling read to report the created instance type 't3.small.search', got {instance_type!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _domain_name(ctx: Any) -> str:
    name = ctx.unique_name("sim2real-osrbk-").lower()
    return name[:28].rstrip("-")


def _create_domain(ctx, domain_name: str) -> None:
    client = ctx.client("opensearch")
    client.create_domain(
        DomainName=domain_name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
    )

    def _cleanup() -> None:
        try:
            client.delete_domain(DomainName=domain_name)
        except client.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup)


_IN_PROGRESS = (
    "A change/update is in progress. Please wait for it to complete before requesting another change."
)


def _quiescent(status: dict) -> bool:
    """True when DescribeDomain reports no change running on the domain."""
    return (
        status.get("Processing") is False
        and status.get("UpgradeProcessing") is not True
        and status.get("DomainProcessingStatus", "Active") == "Active"
    )


def _rollback_once_settled(ctx, client, domain_name: str):
    """Poll until the domain is quiescent, then call RollbackServiceSoftwareUpdate; AWS keeps
    post-create work running behind Processing=False and refuses with its exact "change/update is
    in progress" message, so that refusal is polled past. Returns (ServiceSoftwareOptions read just
    before the accepted call, the response)."""
    budget = _budget_s(ctx, 300.0)
    deadline = time.monotonic() + budget
    last = None
    while True:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        if _quiescent(status):
            try:
                return (status.get("ServiceSoftwareOptions", {}),
                        client.rollback_service_software_update(DomainName=domain_name))
            except ClientError as err:
                error = err.response["Error"]
                if error.get("Code") != "ValidationException" or error.get("Message") != _IN_PROGRESS:
                    raise AssertionError(
                        "expected a 200 declining the rollback on a settled domain, got "
                        f"{error.get('Code')!r}: {error.get('Message')!r}"
                    ) from err
                last = error.get("Message")
        else:
            last = {k: status.get(k) for k in ("Processing", "UpgradeProcessing", "DomainProcessingStatus")}
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"domain {domain_name} quiescent: the run budget ended first; not graded")
            raise AssertionError(f"domain {domain_name} still had a change in progress after {budget}s: {last!r}")
        time.sleep(2)


def _wait_domain_active(ctx, domain_name: str, timeout_s: float) -> None:
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
