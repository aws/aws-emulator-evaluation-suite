"""registration-code-and-audit-config-readable."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "registration-code-and-audit-config-readable"
GROUP = 'account'
SERVICES = ['iot']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRegistrationCode is stable per account and DescribeAccountAuditConfiguration
    exposes the per-check configuration map."""
    iot = ctx.client("iot")
    code1 = iot.get_registration_code()["registrationCode"]
    code2 = iot.get_registration_code()["registrationCode"]
    assert code1 == code2, "registration code must be stable across calls"
    assert len(code1) >= 32, f"registration code looks too short: {len(code1)}"

    audit = iot.describe_account_audit_configuration()
    assert "auditCheckConfigurations" in audit, audit.keys()
    assert isinstance(audit["auditCheckConfigurations"], dict), (
        f"expected auditCheckConfigurations to be a dict, got {type(audit['auditCheckConfigurations'])}"
    )
    assert "DEVICE_CERTIFICATE_EXPIRING_CHECK" in audit["auditCheckConfigurations"], (
        sorted(audit["auditCheckConfigurations"].keys())
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
