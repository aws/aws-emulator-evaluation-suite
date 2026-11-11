"""code-security-scan-configuration-create-get-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "code-security-scan-configuration-create-get-delete-lifecycle"
GROUP = "state"
SERVICES = ["inspector2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCodeSecurityScanConfiguration's settings are exactly reflected by GetCodeSecurityScanConfiguration."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-codescan-")

    created = inspector2.create_code_security_scan_configuration(
        name=name,
        level="ACCOUNT",
        configuration={
            "ruleSetCategories": ["SAST", "SCA"],
            "periodicScanConfiguration": {"frequency": "WEEKLY"},
            "continuousIntegrationScanConfiguration": {"supportedEvents": ["PULL_REQUEST"]},
        },
        tags={"Owner": "sim2real", "Stage": "test"},
    )
    arn = created["scanConfigurationArn"]
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            inspector2.delete_code_security_scan_configuration(scanConfigurationArn=arn)

    ctx.on_cleanup(_cleanup)

    got = inspector2.get_code_security_scan_configuration(scanConfigurationArn=arn)
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["level"] == "ACCOUNT", f"expected level 'ACCOUNT', got {got['level']!r}"
    assert sorted(got["configuration"]["ruleSetCategories"]) == [
        "SAST",
        "SCA",
    ], f"expected ruleSetCategories ['SAST', 'SCA'], got {sorted(got['configuration']['ruleSetCategories'])!r}"
    assert (
        got["configuration"]["periodicScanConfiguration"]["frequency"] == "WEEKLY"
    ), f"expected periodic frequency 'WEEKLY', got {got['configuration']['periodicScanConfiguration']['frequency']!r}"
    ci_events = got["configuration"]["continuousIntegrationScanConfiguration"]["supportedEvents"]
    assert ci_events == ["PULL_REQUEST"], f"expected supportedEvents ['PULL_REQUEST'], got {ci_events!r}"

    inspector2.delete_code_security_scan_configuration(scanConfigurationArn=arn)
    deleted["done"] = True

    code, msg = _error_code(
        lambda: inspector2.get_code_security_scan_configuration(scanConfigurationArn=arn)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert msg == "Scan configuration not found", msg

    # A mutation on the dead id must also fail, not just the read.
    delete_code, delete_msg = _error_code(
        lambda: inspector2.delete_code_security_scan_configuration(scanConfigurationArn=arn)
    )
    assert (
        delete_code == "ResourceNotFoundException"
    ), f"expected re-delete of dead arn to fail with ResourceNotFoundException, got {delete_code!r}"
    assert delete_msg == "Scan configuration not found", delete_msg


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
