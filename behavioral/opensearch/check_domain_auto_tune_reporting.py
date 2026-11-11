"""domain-auto-tune-reporting."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-auto-tune-reporting"
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
        TagList=[{"Key": "sim2real", "Value": CHECK}],
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
    """DescribeDomainAutoTunes reports the Auto-Tune recommendation/action history
    for a live domain; the same call against a domain that doesn't exist 404s
    rather than returning an empty history."""
    osc = ctx.client("opensearch")
    # Deliberate jitter: concurrent CreateDomain calls in one account in lockstep invite
    # ThrottlingException. Not a poll substitute.
    time.sleep(random.uniform(0, 20.0))
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)
    _wait_domain_active(ctx, osc, domain)

    resp = osc.describe_domain_auto_tunes(DomainName=domain)
    assert "AutoTunes" in resp, f"expected an AutoTunes field, got {resp}"
    autotunes = resp["AutoTunes"]
    assert isinstance(autotunes, list), f"expected AutoTunes to be a list, got {autotunes!r}"
    # A freshly-active idle domain has taken no Auto-Tune action yet: its history is empty, and
    # stays empty on an independent repeat.
    assert autotunes == [], f"expected no Auto-Tune history for a fresh idle domain, got {autotunes!r}"
    resp2 = osc.describe_domain_auto_tunes(DomainName=domain)
    assert resp2["AutoTunes"] == [], f"expected a stable empty AutoTunes read, got {resp2['AutoTunes']!r}"

    # Overly-permissive boundary: a domain that was never created must 404.
    missing = ctx.unique_name("sim2real-behav-os-missing-")[:28].rstrip("-")
    code, message = _error(lambda: osc.describe_domain_auto_tunes(DomainName=missing))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Domain not found: {missing}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
