"""create-code-security-scan-configuration-invalid-rule-set-category-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-code-security-scan-configuration-invalid-rule-set-category-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCodeSecurityScanConfiguration with a ruleSetCategories value outside IAC/SAST/SCA
    fails with ValidationException and the exact enum message and creates nothing, while a valid
    category succeeds."""
    inspector2 = ctx.client("inspector2")
    bad_name = ctx.unique_name("sim2real-codescan-badenum-")
    good_name = ctx.unique_name("sim2real-codescan-goodenum-")

    code, msg = _error_code(
        lambda: inspector2.create_code_security_scan_configuration(
            name=bad_name,
            level="ACCOUNT",
            configuration={
                "ruleSetCategories": ["NOT_A_REAL_RULE_SET_CATEGORY"],
                "periodicScanConfiguration": {"frequency": "WEEKLY"},
            },
        )
    )
    assert code == "ValidationException", f"code={code!r}"
    assert msg == (
        "1 validation error detected: Value at 'configuration.ruleSetCategories' failed to satisfy "
        "constraint: Member must satisfy constraint: [Member must satisfy enum value set: [IAC, SAST, SCA]]"
    ), msg

    # Effect absent: no configuration with the rejected name was created.
    names = {c["name"] for c in _all_scan_configs(inspector2)}
    assert bad_name not in names, "a scan configuration was created despite the invalid rule set category"

    # Positive control: a configuration with real rule set categories is created successfully.
    good = inspector2.create_code_security_scan_configuration(
        name=good_name,
        level="ACCOUNT",
        configuration={
            "ruleSetCategories": ["SAST", "SCA"],
            "periodicScanConfiguration": {"frequency": "WEEKLY"},
        },
        tags={"Owner": "sim2real", "Stage": "test"},
    )
    ctx.on_cleanup(
        lambda: inspector2.delete_code_security_scan_configuration(
            scanConfigurationArn=good["scanConfigurationArn"]
        )
    )
    names_after = _poll_until(
        lambda: {c["name"] for c in _all_scan_configs(inspector2)},
        lambda names: good_name in names,
        timeout_s=30,
        interval_s=3,
    )
    assert good_name in names_after, f"{good_name!r} never appeared in list_code_security_scan_configurations"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={value!r}")


def _all_scan_configs(inspector2):
    items = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_code_security_scan_configurations(**kwargs)
        items.extend(resp.get("configurations", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


