"""certificate-status-transitions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-status-transitions"
GROUP = 'certificate-lifecycle'
SERVICES = ['iot']


def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises.

    Raises AssertionError when the call succeeds.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _cleanup_certificate(iot, cert_id):
    """Deactivate then force-delete a certificate (an ACTIVE cert refuses deletion)."""
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCertificate drives INACTIVE -> ACTIVE -> REVOKED and DescribeCertificate reflects each state.

    DeleteCertificate then proves REVOKED is not just a status word: the certificate becomes
    unreachable by an independent read and unusable by a further mutation.
    """
    iot = ctx.client("iot")
    resp = iot.create_keys_and_certificate(setAsActive=False)
    cert_id = resp["certificateId"]
    ctx.on_cleanup(lambda: _cleanup_certificate(iot, cert_id))

    desc = iot.describe_certificate(certificateId=cert_id)
    status = desc["certificateDescription"]["status"]
    assert status == "INACTIVE", f"expected INACTIVE after create(setAsActive=False), got {status}"

    iot.update_certificate(certificateId=cert_id, newStatus="ACTIVE")
    desc2 = iot.describe_certificate(certificateId=cert_id)
    status2 = desc2["certificateDescription"]["status"]
    assert status2 == "ACTIVE", f"expected ACTIVE after UpdateCertificate(newStatus=ACTIVE), got {status2}"

    iot.update_certificate(certificateId=cert_id, newStatus="REVOKED")
    desc3 = iot.describe_certificate(certificateId=cert_id)
    status3 = desc3["certificateDescription"]["status"]
    assert status3 == "REVOKED", f"expected REVOKED after UpdateCertificate(newStatus=REVOKED), got {status3}"

    iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    code, message = _err(lambda: iot.describe_certificate(certificateId=cert_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeCertificate on a deleted certificate, got {code!r}"
    )
    expected = f"CertificateId {cert_id} does not exist"
    assert message == expected, f"DescribeCertificate message {message!r} != {expected!r}"

    code, message = _err(lambda: iot.update_certificate(certificateId=cert_id, newStatus="ACTIVE"))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateCertificate on a deleted certificate, got {code!r}"
    )
    expected = f"CertificateId {cert_id} does not exist"
    assert message == expected, f"UpdateCertificate message {message!r} != {expected!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
