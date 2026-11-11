"""search-vulnerabilities-returns-matching-cve."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-vulnerabilities-returns-matching-cve"
GROUP = "data-plane"
SERVICES = ["inspector2"]

# CVE-2021-44228 (Log4Shell) is a permanent, well-known entry in Amazon Inspector's
# vulnerability intelligence database -- a stable target for a deterministic query.
_KNOWN_CVE = "CVE-2021-44228"

# SearchVulnerabilities answers AccessDeniedException("Invoking account is not
# enabled") until the account has onboarded to Inspector2 for at least one
# resource type -- an account-wide activation, not a resource-specific one.
_RESOURCE_TYPE = "LAMBDA_CODE"


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control", "resource:account-singleton:inspector2")
def run(ctx) -> None:
    """SearchVulnerabilities returns real vulnerability intelligence data for a well-known CVE."""
    inspector2 = ctx.client("inspector2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    original_status = _resource_status(inspector2, account_id, _RESOURCE_TYPE)
    if original_status != "ENABLED":
        inspector2.enable(resourceTypes=[_RESOURCE_TYPE])

        def _restore():
            inspector2.disable(resourceTypes=[_RESOURCE_TYPE])

        ctx.on_cleanup(_restore)
        _poll_until(
            lambda: _resource_status(inspector2, account_id, _RESOURCE_TYPE),
            lambda s: s == "ENABLED",
            timeout_s=120,
            interval_s=3,
        )

    resp = inspector2.search_vulnerabilities(filterCriteria={"vulnerabilityIds": [_KNOWN_CVE]})
    vulns = resp.get("vulnerabilities", [])
    assert len(vulns) == 1, f"expected exactly one result for {_KNOWN_CVE}, got {len(vulns)}"

    vuln = vulns[0]
    assert vuln["id"] == _KNOWN_CVE, f"expected id {_KNOWN_CVE}, got {vuln.get('id')!r}"
    assert vuln.get("description"), "expected a non-empty description for a well-known CVE"
    assert "cvss2" in vuln or "cvss3" in vuln, (
        f"expected some CVSS scoring data for {_KNOWN_CVE}, got keys={sorted(vuln.keys())}"
    )


def _resource_status(inspector2, account_id: str, resource_type: str) -> str:
    resp = inspector2.batch_get_account_status(accountIds=[account_id])
    accounts = resp["accounts"]
    assert len(accounts) == 1, f"expected exactly one account in response, got {len(accounts)}"
    resource_state = accounts[0]["resourceState"]
    key = "lambdaCode" if resource_type == "LAMBDA_CODE" else resource_type.lower()
    return resource_state[key]["status"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
