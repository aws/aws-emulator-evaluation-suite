"""service-software-update-lifecycle."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-software-update-lifecycle"
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Start/Cancel/RollbackServiceSoftwareUpdate drive one DeploymentStatus state machine; whether or
    not an update is available, a rollback with nothing in progress is refused (ValidationException
    while busy, or a 200 with RollbackAvailable=False)."""
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)
    _wait_domain_active(ctx, osc, domain)

    started_ok = False
    try:
        start_resp = osc.start_service_software_update(DomainName=domain)
        opts = start_resp["ServiceSoftwareOptions"]
        assert opts.get("UpdateStatus"), f"expected an UpdateStatus, got {opts}"
        started_ok = True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ValidationException", (
            f"expected ValidationException when domain isn't eligible for an update, got {code}"
        )
        assert message == "The domain is not available for update.", (
            f"unexpected StartServiceSoftwareUpdate refusal message: {message!r}"
        )

    if started_ok:
        cancel_resp = osc.cancel_service_software_update(DomainName=domain)
        cancel_opts = cancel_resp["ServiceSoftwareOptions"]
        assert cancel_opts.get("UpdateStatus") in (
            "NOT_ELIGIBLE",
            "COMPLETED",
            "ELIGIBLE",
        ), f"expected update to be cancelled off the in-progress path, got {cancel_opts}"

    # Overly-permissive boundary: rolling back when there is no eligible
    # in-progress deployment must be rejected rather than silently accepted.
    before_rollback = osc.describe_domain(DomainName=domain)["DomainStatus"]["ServiceSoftwareOptions"]
    try:
        rollback_resp = osc.rollback_service_software_update(DomainName=domain)
    except ClientError as exc:
        # Real AWS refuses while the domain still runs post-create work behind Processing=False.
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ValidationException", (
            f"expected ValidationException (or a 200 declining with RollbackAvailable=False), got {code!r}"
        )
        assert message == (
            "A change/update is in progress. Please wait for it to complete before requesting "
            "another change."
        ), f"unexpected rollback refusal message: {message!r}"
    else:
        # On a settled domain real AWS answers 200 and declines the rollback in the payload.
        rollback_opts = rollback_resp.get("RollbackServiceSoftwareOptions", {})
        assert rollback_opts.get("RollbackAvailable") is False, (
            f"expected the 200 to decline the rollback with RollbackAvailable=False, got {rollback_opts!r}"
        )
        assert rollback_opts.get("Description") == (
            "No previous software version available for rollback. Please contact AWS Support for "
            "assistance."
        ), f"unexpected rollback decline description: {rollback_opts.get('Description')!r}"

    # Independent read at the destination: the rejected call must not have moved the
    # state machine it targeted.
    after_rollback = osc.describe_domain(DomainName=domain)["DomainStatus"]["ServiceSoftwareOptions"]
    assert after_rollback == before_rollback, (
        f"a rejected RollbackServiceSoftwareUpdate changed ServiceSoftwareOptions: "
        f"{before_rollback!r} -> {after_rollback!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
