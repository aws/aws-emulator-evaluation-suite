"""scheduled-action-listing."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scheduled-action-listing"
GROUP = 'domain'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


# Marks a resource state the target accepted and never converged, so it reads as the
# target's own fault rather than a slow environment.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state: a failure on every target.

    The message carries the sentinel so the failure is attributed to the target.
    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


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
        TagList=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav-os"},
        ],
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
    """Poll until Processing=False and Created=True. On real AWS a domain needs
    10-20 min to go Active (over the per-check ceiling), so this wait runs only
    it never settles; on an emulator the domain settles fast and the check runs.
    """
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} never became Active within {budget}s",
    )


def _error(fn) -> tuple:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListScheduledActions returns well-formed actions for a real domain and 404s for a missing one;
    the SERVICE_SOFTWARE_UPDATE entry is cross-checked against DescribeDomain's independently
    derived ServiceSoftwareOptions.UpdateAvailable."""
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)
    _wait_domain_active(ctx, osc, domain)

    resp = osc.list_scheduled_actions(DomainName=domain)
    actions = resp["ScheduledActions"]
    for a in actions:
        assert a.get("Id"), a
        assert a.get("Type") in (
            "SERVICE_SOFTWARE_UPDATE",
            "JVM_HEAP_SIZE_TUNING",
            "JVM_YOUNG_GEN_TUNING",
        ), a
        assert a.get("Status") in (
            "PENDING_UPDATE",
            "IN_PROGRESS",
            "FAILED",
            "COMPLETED",
            "NOT_ELIGIBLE",
            "ELIGIBLE",
        ), a

    # An accept-set check alone cannot fail: any value a target invents is in the
    # modelled enum, and an empty list runs zero iterations of the loop above. Tie
    # the SERVICE_SOFTWARE_UPDATE entry's presence to an independent read of the
    # domain's own reported update eligibility -- a target that fabricates entries,
    # or one that always returns an empty list, disagrees with this.
    dom_status = osc.describe_domain(DomainName=domain)["DomainStatus"]
    update_available = bool(dom_status.get("ServiceSoftwareOptions", {}).get("UpdateAvailable"))
    has_sw_update_action = any(a.get("Type") == "SERVICE_SOFTWARE_UPDATE" for a in actions)
    assert has_sw_update_action == update_available, (
        f"ListScheduledActions SERVICE_SOFTWARE_UPDATE presence ({has_sw_update_action}) "
        f"disagrees with DescribeDomain ServiceSoftwareOptions.UpdateAvailable ({update_available})"
    )

    # Overly-permissive boundary: a domain that doesn't exist must 404 rather
    # than return an empty list.
    missing = ctx.unique_name("sim2real-behav-os-missing-")[:28].rstrip("-")
    code, message = _error(lambda: osc.list_scheduled_actions(DomainName=missing))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Domain not found: {missing}", f"unexpected not-found message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
