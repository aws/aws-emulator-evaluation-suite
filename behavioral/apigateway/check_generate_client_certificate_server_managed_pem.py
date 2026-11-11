"""generate-client-certificate-server-managed-pem."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "generate-client-certificate-server-managed-pem"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GenerateClientCertificate issues a real server-generated PEM certificate with a genuine
    future expiration date, retrievable byte-for-byte via GetClientCertificate, and the
    certificate is truly gone (not merely marked inactive) once deleted."""
    apigw = ctx.client("apigateway")

    resp = apigw.generate_client_certificate(
        description=ctx.unique_name("sim2real-cert-"),
        tags={"sim2real": "generate-client-certificate-server-managed-pem"},
    )
    cert_id = resp["clientCertificateId"]
    cleanup_state = {"deleted": False}
    ctx.on_cleanup(
        lambda: None if cleanup_state["deleted"] else apigw.delete_client_certificate(clientCertificateId=cert_id)
    )

    pem = resp["pemEncodedCertificate"]
    created = resp["createdDate"]
    expiration = resp["expirationDate"]

    assert pem.strip().startswith("-----BEGIN CERTIFICATE-----"), pem[:40]
    assert pem.strip().endswith("-----END CERTIFICATE-----"), pem[-40:]
    assert isinstance(created, dt.datetime) and isinstance(expiration, dt.datetime)
    assert expiration > created, "expirationDate must be after createdDate"
    assert (expiration - created).days > 300, "a real client certificate should be valid for close to a year"

    fetched = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert fetched["pemEncodedCertificate"] == pem
    assert fetched["expirationDate"] == expiration
    assert fetched["createdDate"] == created

    apigw.delete_client_certificate(clientCertificateId=cert_id)
    cleanup_state["deleted"] = True
    code, message = _error(lambda: apigw.get_client_certificate(clientCertificateId=cert_id))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "Invalid client certificate id specified", (
        f"unexpected NotFoundException message {message!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected ClientError, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
