"""create-template-nonexistent-connector-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-template-nonexistent-connector-not-found"
GROUP = "not-found"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTemplate on a well-formed nonexistent ConnectorArn gets ResourceNotFoundException
    "Connector was not found: <arn>.", while a malformed Name on the same ARN gets ValidationException
    with its exact message; ListConnectors succeeds."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    connector_arn = f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/{uuid.uuid4()}"
    name = ctx.unique_name("sim2real-tmpl-")

    code, message = _error_code(
        lambda: pcad.create_template(
            ConnectorArn=connector_arn, Name=name, Definition=_template_v2_definition()
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Connector was not found: {connector_arn}.", message

    # positive control: the SAME nonexistent connector, but a malformed Name (a comma is
    # explicitly disallowed), must be rejected with ValidationException instead -- proving
    # CreateTemplate discriminates by failure class rather than returning
    # ResourceNotFoundException unconditionally.
    control_code, control_message = _error_code(
        lambda: pcad.create_template(
            ConnectorArn=connector_arn, Name="bad,name", Definition=_template_v2_definition()
        )
    )
    assert control_code == "ValidationException", f"expected ValidationException, got {control_code}"
    assert control_message == (
        '[ECMA 262 regex "^(?!^\\s+$)((?![\\x5c\'\\x2b,;<=>#\\x22])([\\x20-\\x7E]))+$" '
        'does not match input string "bad,name"]'
    ), control_message

    control = pcad.list_connectors()
    assert "Connectors" in control, f"expected 'Connectors' key in response, got {control!r}"


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
    """Call fn(); return its error (code, message). A success raises, because a target that
    accepts what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
