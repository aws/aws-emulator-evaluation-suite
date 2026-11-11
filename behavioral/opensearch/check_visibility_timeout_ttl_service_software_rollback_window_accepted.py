"""visibility-timeout-ttl-service-software-rollback-window-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "visibility-timeout-ttl-service-software-rollback-window-accepted"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "plane:control")
def run(ctx) -> None:
    """RollbackServiceSoftwareUpdate on a fresh domain with no prior software version returns 200
    with RollbackAvailable=False and leaves CurrentVersion unchanged, rather than raising an error.
    No rollback window or other period elapses; the call is made once the new domain settles.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_RollbackServiceSoftwareUpdate.html
    """
    opensearch = ctx.client("opensearch")
    name = _domain_name(ctx, "rollback")
    opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=name))
    domain_status = _wait_domain_active(ctx, name)
    domain_status = _wait_service_software_settled(ctx, name, domain_status)

    sso = domain_status.get("ServiceSoftwareOptions", {})
    assert not sso.get("RollbackAvailable", False), (
        "test precondition violated: freshly created domain unexpectedly reports "
        "RollbackAvailable=True"
    )
    current_version_before = sso.get("CurrentVersion")

    try:
        response = opensearch.rollback_service_software_update(DomainName=name)
    except ClientError as err:
        raise AssertionError(
            "expected RollbackServiceSoftwareUpdate to complete (200) with "
            f"RollbackAvailable=False outside the rollback window, got "
            f"{err.response['Error']['Code']!r} instead"
        ) from err
    rollback_options = response.get("RollbackServiceSoftwareOptions", {})
    assert rollback_options.get("RollbackAvailable") is False, (
        "expected RollbackServiceSoftwareOptions.RollbackAvailable=False in the response "
        f"for a domain with nothing to roll back, got {rollback_options!r}"
    )
    assert rollback_options.get("CurrentVersion") == current_version_before, (
        f"CurrentVersion in the rollback response ({rollback_options.get('CurrentVersion')!r}) "
        f"disagrees with the domain's own reported version ({current_version_before!r})"
    )

    # Effect is absent: the domain's software version is unchanged by the no-op call.
    after = opensearch.describe_domain(DomainName=name)["DomainStatus"]
    after_version = after.get("ServiceSoftwareOptions", {}).get("CurrentVersion")
    assert after_version == current_version_before, (
        f"CurrentVersion changed from {current_version_before!r} to {after_version!r} as a "
        "side effect of the no-op rollback call"
    )

    # Positive control: a genuinely valid mutation on the SAME domain still succeeds,
    # proving the domain isn't just rejecting every call.
    opensearch.update_domain_config(
        DomainName=name,
        AdvancedOptions={"rest.action.multi.allow_explicit_index": "true"},
    )


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


def _wait_service_software_settled(
    ctx, name: str, first: dict, timeout_s: float = 300.0, interval_s: float = 20.0
) -> dict:
    """Freeze detector: `Created`/`Processing` flip before ServiceSoftwareOptions has
    necessarily finished its own post-creation initialization, so require 3 consecutive
    identical reads of it before trusting RollbackAvailable/CurrentVersion as settled."""
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    streak = [first.get("ServiceSoftwareOptions", {})]
    last = first
    while time.monotonic() < deadline:
        if len(streak) >= 3:
            return last
        time.sleep(interval_s)
        last = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        current = last.get("ServiceSoftwareOptions", {})
        if current == streak[-1]:
            streak.append(current)
        else:
            streak = [current]
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
