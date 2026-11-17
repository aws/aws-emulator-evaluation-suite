"""update-certificate-revoked-to-active-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "update-certificate-revoked-to-active-rejected"
GROUP = "certificate-lifecycle"
SERVICES = ["iot"]


def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_certificate(iot, cert_id):
    """Teardown: force-delete regardless of status; a missing certificate is clean."""
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCertificate refuses moving a REVOKED certificate back to ACTIVE with
    CertificateStateException, and the certificate stays REVOKED."""
    iot = ctx.client("iot")
    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    # Positive control: the caller-settable transitions that lead up to REVOKED work.
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    ctrl = iot.describe_certificate(certificateId=cert_id)
    assert ctrl["certificateDescription"]["status"] == "INACTIVE", (
        f"positive control: expected INACTIVE, got {ctrl['certificateDescription']['status']!r}"
    )

    iot.update_certificate(certificateId=cert_id, newStatus="REVOKED")
    ctrl2 = iot.describe_certificate(certificateId=cert_id)
    assert ctrl2["certificateDescription"]["status"] == "REVOKED", (
        f"positive control: expected REVOKED, got {ctrl2['certificateDescription']['status']!r}"
    )

    code, message = _error(
        lambda: iot.update_certificate(certificateId=cert_id, newStatus="ACTIVE")
    )
    assert code == "CertificateStateException", f"expected CertificateStateException, got {code!r}"
    assert message == "Not allowed to update from REVOKED status using UpdateCertificate call", message

    # unchanged: still REVOKED
    desc = iot.describe_certificate(certificateId=cert_id)
    assert desc["certificateDescription"]["status"] == "REVOKED", (
        f"expected status unchanged at REVOKED after the rejected transition, got {desc['certificateDescription']['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
