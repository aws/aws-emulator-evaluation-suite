"""hsm-configuration-certificate-text-preserved."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "hsm-configuration-certificate-text-preserved"
GROUP = "representation"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Description (unicode, special chars, a certificate-like blob) and HsmPartitionName
    round-trip byte-exact through DescribeHsmConfigurations, with no truncation or escaping.
    """
    rs = ctx.client("redshift")
    hsm_id = ctx.unique_name("sim2real-hsm-").lower().replace("_", "-")

    fake_cert_blob = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A<special>&amp;chars\"'\\/\n"
        "unicode: h\u00e9llo \u4e16\u754c \U0001f680 \u00fc\u00f1\u00ee\u00e7\u00f8d\u00e9\n"
        "line-with-tab:\tend\n"
        "-----END CERTIFICATE-----"
    )
    description = "HSM cert w/ special chars: <tag>&amp;\"quoted\"\u2014h\u00e9llo\u4e16\u754c\U0001f680\n" + fake_cert_blob
    # HsmPartitionName is validated by the service as a "name" field (printable
    # ASCII only) -- unicode there is rejected outright, so the unicode/special
    # character probe lives in Description, which is unbounded free text.
    partition_name = "sim2real-partition-ascii"

    rs.create_hsm_configuration(
        HsmConfigurationIdentifier=hsm_id,
        Description=description,
        HsmIpAddress="203.0.113.5",
        HsmPartitionName=partition_name,
        HsmPartitionPassword="Passw0rd!Sim2Real",
        HsmServerPublicCertificate=fake_cert_blob,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_hsm_configuration(rs, hsm_id))

    # HsmServerPublicCertificate and HsmPartitionPassword are write-only and never echoed back.
    described = rs.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)["HsmConfigurations"][0]

    assert described["Description"] == description, "Description drifted on round-trip"
    assert described["HsmPartitionName"] == partition_name, "HsmPartitionName drifted on round-trip"
    assert described["HsmIpAddress"] == "203.0.113.5", (
        f"expected HsmIpAddress 203.0.113.5, got {described['HsmIpAddress']!r}"
    )
    assert described["HsmConfigurationIdentifier"] == hsm_id, (
        f"expected HsmConfigurationIdentifier {hsm_id!r}, got {described['HsmConfigurationIdentifier']!r}"
    )


def _delete_hsm_configuration(rs: Any, hsm_id: str) -> None:
    try:
        rs.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "HsmConfigurationNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
