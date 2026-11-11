"""get-registry-scanning-configuration-invalid-filter-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-registry-scanning-configuration-invalid-filter-rejected"
GROUP = "negative-classes"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """An out-of-range scanning configuration repository filter type is rejected with
    InvalidParameterException and does not get persisted, while a valid filter type
    (WILDCARD) in the same shape still succeeds (control)."""
    ecr = ctx.client("ecr")

    baseline = ecr.get_registry_scanning_configuration()["scanningConfiguration"]

    def _restore():
        ecr.put_registry_scanning_configuration(
            scanType=baseline.get("scanType", "BASIC"), rules=baseline.get("rules", [])
        )

    ctx.on_cleanup(_restore)

    bad_filter_value = f"sim2real-{uuid.uuid4().hex[:10]}*"
    bad_rules = [
        {
            "scanFrequency": "SCAN_ON_PUSH",
            "repositoryFilters": [
                {"filter": bad_filter_value, "filterType": "REGEX_NOT_SUPPORTED"}
            ],
        }
    ]

    code, message = _error(
        lambda: ecr.put_registry_scanning_configuration(scanType="BASIC", rules=bad_rules)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for filterType {bad_rules[0]['repositoryFilters'][0]['filterType']!r}, got {code!r}"
    )
    assert message == (
        "Invalid parameter at 'rules.1.member.repositoryFilters.1.member.filterType' failed to satisfy constraint: 'Member must satisfy enum value set: [WILDCARD]'"
    ), message

    # effect absent: configuration unchanged from baseline
    after_bad = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert after_bad == baseline, (
        f"invalid filter type configuration was partially applied: expected {baseline!r}, got {after_bad!r}"
    )

    # positive control: the same shape with a valid filterType succeeds
    good_filter_value = f"sim2real-{uuid.uuid4().hex[:10]}*"
    good_rules = [
        {
            "scanFrequency": "SCAN_ON_PUSH",
            "repositoryFilters": [{"filter": good_filter_value, "filterType": "WILDCARD"}],
        }
    ]
    put_resp = ecr.put_registry_scanning_configuration(scanType="BASIC", rules=good_rules)
    assert put_resp["registryScanningConfiguration"]["rules"] == good_rules, (
        f"expected {good_rules!r}, got {put_resp['registryScanningConfiguration']['rules']!r}"
    )

    get_resp = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert get_resp["rules"] == good_rules, f"expected {good_rules!r}, got {get_resp['rules']!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
