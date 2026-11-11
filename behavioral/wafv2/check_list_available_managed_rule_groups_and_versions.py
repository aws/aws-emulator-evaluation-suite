"""list-available-managed-rule-groups-and-versions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-available-managed-rule-groups-and-versions"
GROUP = 'managed-rule-groups'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0, codes=None):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable)."""
    retryable = codes or _TRANSIENT_CODES
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in retryable:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc

def _list_all(list_fn, key, scope=SCOPE):
    """Fully paginate one of the WAFv2 List* operations (marker-paginated, 100/page)."""
    items = []
    marker = None
    while True:
        kwargs = {"Scope": scope, "Limit": 100}
        if marker:
            kwargs["NextMarker"] = marker
        resp = list_fn(**kwargs)
        page = resp.get(key, [])
        items.extend(page)
        marker = resp.get("NextMarker")
        if not marker or not page:
            break
    return items

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The AWS managed rule group catalog is non-empty and versions are listable."""
    w = ctx.client("wafv2")
    groups = _list_all(w.list_available_managed_rule_groups, "ManagedRuleGroups")
    names = {(g["VendorName"], g["Name"]) for g in groups}
    assert ("AWS", "AWSManagedRulesCommonRuleSet") in names, sorted(names)[:10]

    versions = _retry_transient(
        lambda: w.list_available_managed_rule_group_versions(
            VendorName="AWS", Name="AWSManagedRulesCommonRuleSet", Scope=SCOPE, Limit=10
        )
    )
    assert "CurrentDefaultVersion" in versions, versions
    default_version = versions["CurrentDefaultVersion"]
    listed = [v["Name"] for v in versions.get("Versions", [])]
    assert listed, (
        f"AWSManagedRulesCommonRuleSet is versioned but "
        f"ListAvailableManagedRuleGroupVersions returned no Versions: {versions}"
    )
    assert default_version in listed, (
        f"CurrentDefaultVersion {default_version!r} is not among the listed versions {listed}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
