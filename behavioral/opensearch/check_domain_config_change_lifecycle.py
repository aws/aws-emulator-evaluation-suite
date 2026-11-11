"""domain-config-change-lifecycle."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-config-change-lifecycle"
GROUP = 'domain'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_CANCEL_IN_FLIGHT = "CancelDomainConfigChange only allowed when domain's config change status is in ValidationFailed."
_CANCEL_NOT_MODIFYING = "CancelDomainConfigChange only when domain state is in Modifying or UpdatingServiceSoftware."
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _never_ready(msg: str):
    """A resource accepted but never ready; returned so a call site keeps ``from exc`` chaining."""
    return AssertionError(msg)


def _minimal_domain_kwargs(domain_name, *, vpc_options=None, engine_version=ENGINE_VERSION) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=engine_version,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    if vpc_options is not None:
        kwargs["VPCOptions"] = vpc_options
    return kwargs


def _create_domain(ctx, osc, domain_name, **overrides) -> dict:
    kwargs = _minimal_domain_kwargs(domain_name, **overrides)
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
    """Poll until the domain finishes provisioning (Processing=False, Created=True).

    A real OpenSearch domain needs 10-20 min to go Active, hence the long budget.
    """
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # DescribeDomain throttles under the suite's concurrent polls: poll again to the deadline.
            if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to become Active: the run budget ended first; not graded")
    raise _never_ready(
        f"domain {domain_name} never became Active within {budget}s",
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDomainConfig starts a change DescribeDomainChangeProgress reports; a successful
    CancelDomainConfigChange keeps InstanceCount 1, else it reaches 2; progress ends terminal."""
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)
    _wait_domain_active(ctx, osc, domain)

    initial_cfg = osc.describe_domain_config(DomainName=domain)["DomainConfig"]
    assert initial_cfg["ClusterConfig"]["Options"]["InstanceCount"] == 1

    # A domain that just went Active can briefly still report "A change/update is in progress"
    # as ValidationException, so retry with a short backoff.
    def _try_update() -> bool:
        """True once accepted; False while refused with ValidationException; any other error raises."""
        try:
            osc.update_domain_config(
                DomainName=domain,
                ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 2},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            return False
        return True

    accepted = _try_update()
    update_deadline = time.monotonic() + _budget_s(ctx, 30.0)
    while not accepted and time.monotonic() < update_deadline:
        time.sleep(1)
        accepted = _try_update()
    if not accepted and _budget_spent(ctx):
        raise TimeoutError(f"UpdateDomainConfig on {domain} to be accepted: the run budget ended first; not graded")
    assert accepted, "UpdateDomainConfig failed: ValidationException"

    progress = osc.describe_domain_change_progress(DomainName=domain)["ChangeProgressStatus"]
    started_status = progress.get("Status")
    # A change just kicked off is in flight, or already COMPLETED when the target applies it
    # faster than this read; the final InstanceCount must then match the cancel outcome. Never FAILED.
    assert started_status in ("PENDING", "PROCESSING", "COMPLETED"), (
        f"a change just kicked off by UpdateDomainConfig should be PENDING/PROCESSING "
        f"(or COMPLETED), got Status={started_status!r}"
    )

    # Only a change that failed validation is cancellable; a valid one is refused, and the
    # refusal names whether the change is still applying or already applied.
    try:
        osc.cancel_domain_config_change(DomainName=domain)
        cancel_code = None
    except ClientError as exc:
        cancel_code = exc.response["Error"]["Code"]
        cancel_message = exc.response["Error"].get("Message")
    if cancel_code is not None:
        assert cancel_code == "ValidationException", f"expected ValidationException or success, got {cancel_code}"
        if cancel_message != _CANCEL_IN_FLIGHT:
            assert cancel_message == _CANCEL_NOT_MODIFYING, f"CancelDomainConfigChange message: {cancel_message!r}"
    cancel_succeeded = cancel_code is None

    # Scaling InstanceCount 1->2 is a blue/green deployment that takes 10-30 min on AWS.
    settled = None
    budget = _budget_s(ctx, 1800.0)
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        settled = osc.describe_domain_config(DomainName=domain)["DomainConfig"]
        if settled["ClusterConfig"]["Status"]["State"] not in ("Processing",):
            break
        time.sleep(2.0)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f"domain {domain} config change to settle: the run budget ended first; not graded")
        raise _never_ready(
            f"domain {domain} config change never settled within {budget}s (last "
            f"ClusterConfig.Status.State="
            f"{(settled or {}).get('ClusterConfig', {}).get('Status', {}).get('State')!r})",
        )
    final_count = settled["ClusterConfig"]["Options"]["InstanceCount"]
    # Branch on the observed cancel outcome rather than accepting either count.
    if cancel_succeeded:
        assert final_count == 1, (
            f"CancelDomainConfigChange reported success, so the pending InstanceCount "
            f"change should have been aborted and InstanceCount should remain 1, got {final_count}"
        )
    else:
        assert final_count == 2, (
            f"CancelDomainConfigChange reported {cancel_code!r} (nothing to cancel), so the "
            f"InstanceCount change should have completed; expected 2, got {final_count}"
        )

    final_progress = osc.describe_domain_change_progress(DomainName=domain)["ChangeProgressStatus"]
    final_status = final_progress.get("Status")
    # ClusterConfig has settled, so change progress must be terminal too; OverallChangeStatus
    # has no CANCELLED value.
    assert final_status in ("COMPLETED", "FAILED"), (
        f"ClusterConfig already settled (State="
        f"{settled['ClusterConfig']['Status']['State']!r}) so the change progress should be "
        f"terminal, got Status={final_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
