"""domain-health-reporting."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-health-reporting"
GROUP = 'domain'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _never_ready(msg: str):
    """A resource accepted but never ready; returned so a call site keeps ``from exc`` chaining."""
    return AssertionError(msg)


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
        TagList=[{"Key": "sim2real", "Value": domain_name}],
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
    raise _never_ready(
        f"domain {domain_name} never became Active within {budget}s",
    )


def _retry_on(fn, *, error_codes=(), message_substrings=(), attempts=6, delay_s=10.0):
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if attempt < attempts - 1 and (
                code in error_codes or any(s in msg for s in message_substrings)
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


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
    """DescribeDomainHealth reports live cluster health and cluster-manager-node fields and
    DescribeDomainNodes enumerates the domain's actual node(s) -- both reflect
    real per-node state; querying either for a domain that doesn't exist 404s."""
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    created = _create_domain(ctx, osc, domain)
    instance_count = created["ClusterConfig"]["InstanceCount"]
    _wait_domain_active(ctx, osc, domain)

    # Once the domain is active, health settles to a serving state: Active, Green or Yellow.
    deadline = time.monotonic() + max(1.0, min(300.0, (ctx.time_left() or 300.0) - 60.0))
    health = osc.describe_domain_health(DomainName=domain)
    while health.get("ClusterHealth") not in ("Green", "Yellow") and time.monotonic() < deadline:
        time.sleep(2)
        health = osc.describe_domain_health(DomainName=domain)
    assert health.get("DomainState") == "Active", f"expected DomainState Active, got {health}"
    assert health.get("ClusterHealth") in ("Green", "Yellow"), f"expected ClusterHealth Green or Yellow, got {health}"
    assert "MasterNode" in health, f"expected a MasterNode field, got keys {sorted(health)}"

    nodes = _retry_on(
        lambda: osc.describe_domain_nodes(DomainName=domain)["DomainNodesStatusList"],
        error_codes=("DependencyFailureException",),
        message_substrings=("not available now",),
        attempts=6,
        delay_s=15.0,
    )
    assert len(nodes) == instance_count, (
        f"expected exactly {instance_count} node(s) (ClusterConfig.InstanceCount), got {len(nodes)}: {nodes}"
    )
    for n in nodes:
        assert n.get("NodeId"), f"node missing NodeId: {n}"

    # A domain that doesn't exist must not report a fabricated/default health
    # payload. Real AWS answers with the generic BaseException envelope rather
    # than ResourceNotFoundException for this operation.
    missing = ctx.unique_name("sim2real-behav-os-missing-")[:28].rstrip("-")
    code, message = _error(lambda: osc.describe_domain_health(DomainName=missing))
    assert code == "BaseException", f"expected BaseException, got {code}"
    expected_message = f"Domain not found: {missing}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
