"""create-template-invalid-name-characters-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-template-invalid-name-characters-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTemplate rejects a Name containing a comma with ValidationException and its exact message,
    while a clean name on the same nonexistent ConnectorArn gets the exact Connector
    ResourceNotFoundException."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    connector_arn = f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/{uuid.uuid4()}"
    definition = _template_v2_definition()

    code, message = _error_code(
        lambda: pcad.create_template(
            ConnectorArn=connector_arn,
            Name="bad,name",
            Definition=definition,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a Name containing a disallowed comma, got {code!r}"
    )
    assert message == (
        '[ECMA 262 regex "^(?!^\\s+$)((?![\\x5c\'\\x2b,;<=>#\\x22])([\\x20-\\x7E]))+$" '
        'does not match input string "bad,name"]'
    ), message

    control_code, control_message = _error_code(
        lambda: pcad.create_template(
            ConnectorArn=connector_arn,
            Name="clean-template-name",
            Definition=definition,
        )
    )
    assert control_code == "ResourceNotFoundException", (
        "expected ResourceNotFoundException for the control call (clean Name, same "
        f"nonexistent ConnectorArn), got {control_code!r}"
    )
    assert control_message == f"Connector was not found: {connector_arn}.", control_message


def _template_v2_definition() -> dict:
    return {
        "TemplateV2": {
            "CertificateValidity": {
                "ValidityPeriod": {"PeriodType": "YEARS", "Period": 1},
                "RenewalPeriod": {"PeriodType": "WEEKS", "Period": 6},
            },
            "PrivateKeyAttributes": {
                "MinimalKeyLength": 2048,
                "KeySpec": "KEY_EXCHANGE",
                "CryptoProviders": ["Microsoft RSA SChannel Cryptographic Provider"],
            },
            "PrivateKeyFlags": {
                "ClientVersion": "WINDOWS_SERVER_2008_R2",
                "ExportableKey": False,
                "StrongKeyProtectionRequired": False,
            },
            "EnrollmentFlags": {
                "UserInteractionRequired": False,
                "IncludeSymmetricAlgorithms": False,
                "RemoveInvalidCertificateFromPersonalStore": False,
                "NoSecurityExtension": False,
                "EnableKeyReuseOnNtTokenKeysetStorageFull": False,
            },
            "SubjectNameFlags": {
                "RequireCommonName": True,
                "RequireDnsAsCn": False,
                "RequireDirectoryPath": False,
                "RequireEmail": False,
                "SanRequireDns": True,
                "SanRequireEmail": False,
                "SanRequireSpn": False,
                "SanRequireUpn": False,
                "SanRequireDirectoryGuid": False,
                "SanRequireDomainDns": False,
            },
            "GeneralFlags": {"AutoEnrollment": False, "MachineType": True},
            "Extensions": {
                "KeyUsage": {
                    "Critical": True,
                    "UsageFlags": {
                        "DigitalSignature": True,
                        "KeyEncipherment": True,
                        "NonRepudiation": False,
                        "DataEncipherment": False,
                        "KeyAgreement": False,
                    },
                }
            },
        }
    }


def _error_code(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
