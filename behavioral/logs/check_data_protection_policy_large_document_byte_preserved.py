"""data-protection-policy-large-document-byte-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "data-protection-policy-large-document-byte-preserved"
GROUP = "representation"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A large data protection policy JSON document (built from the full catalog of
    built-in CloudWatch Logs data identifiers, expanded across their supported region
    codes) is persisted and returned byte-identical, with no reformatting/truncation.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-logs-")
    logs.create_log_group(logGroupName=group, tags={"simparity-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    policy_document = _build_large_policy_document(target_len=8000)
    assert len(policy_document) <= 30720

    logs.put_data_protection_policy(logGroupIdentifier=group, policyDocument=policy_document)
    ctx.on_cleanup(lambda: logs.delete_data_protection_policy(logGroupIdentifier=group))

    got = logs.get_data_protection_policy(logGroupIdentifier=group)["policyDocument"]
    assert got == policy_document, (
        f"policy document not byte-identical: lengths {len(got)} vs {len(policy_document)}, "
        f"first diff at {_first_diff(got, policy_document)}"
    )


def _all_data_identifiers() -> list[str]:
    """A long but valid list of distinct built-in CloudWatch Logs data identifiers
    (language/region-independent ones, plus region-dependent ones expanded across their
    supported country codes) used to pad the policy document to a large size without
    tripping the "conflicting operation for identifier" validation that a repeated
    identifier triggers.
    """
    region_independent = [
        "Address", "AwsSecretKey", "CreditCardExpiration", "CreditCardNumber",
        "CreditCardSecurityCode", "EmailAddress", "IpAddress", "LatLong", "Name",
        "OpenSshPrivateKey", "PgpPrivateKey", "PkcsPrivateKey", "PuttyPrivateKey",
        "VehicleIdentificationNumber",
    ]
    region_dependent = {
        "BankAccountNumber": ["DE", "ES", "FR", "GB", "IT", "US"],
        "DriversLicense": [
            "AT", "AU", "BE", "BG", "CA", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
            "FR", "GB", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL",
            "PL", "PT", "RO", "SE", "SI", "SK", "US",
        ],
        "PassportNumber": ["CA", "DE", "ES", "FR", "GB", "IT", "US"],
        "PhoneNumber": ["BR", "DE", "ES", "FR", "GB", "IT", "US"],
        "Ssn": ["ES", "US"],
    }
    us_only = [
        "DrugEnforcementAgencyNumber", "HealthInsuranceClaimNumber",
        "HealthcareProcedureCode", "IndividualTaxIdentificationNumber",
        "MedicareBeneficiaryNumber", "NationalDrugCode", "NationalProviderId",
        "ZipCode",
    ]
    identifiers = list(region_independent)
    for name, countries in region_dependent.items():
        identifiers.extend(f"{name}-{c}" for c in countries)
    identifiers.extend(f"{name}-US" for name in us_only)
    return sorted(set(identifiers))


def _build_large_policy_document(target_len: int) -> str:
    prefix = "arn:aws:dataprotection::aws:data-identifier/"
    identifiers = [f"{prefix}{name}" for name in _all_data_identifiers()]
    base = {
        "Name": "sim2real-large-dpp",
        "Description": "large document byte-preservation probe",
        "Version": "2021-06-01",
        "Statement": [
            {
                "Sid": "audit-statement",
                "DataIdentifier": identifiers,
                "Operation": {"Audit": {"FindingsDestination": {}}},
            },
            {
                "Sid": "deidentify-statement",
                "DataIdentifier": identifiers,
                "Operation": {"Deidentify": {"MaskConfig": {}}},
            },
        ],
    }
    doc = json.dumps(base)
    assert len(doc) >= target_len, (
        f"built-in identifier set only produced {len(doc)} chars (< target {target_len}); "
        "not enough distinct identifiers exist to pad further without duplication"
    )
    return doc


def _first_diff(a: str, b: str) -> int:
    for i, (ca, cb) in enumerate(zip(a, b)):
        if ca != cb:
            return i
    return min(len(a), len(b))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
