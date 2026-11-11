"""client-certificate-expiration-tracked."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "client-certificate-expiration-tracked"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GenerateClientCertificate yields a PEM certificate valid for exactly 365 days from its createdDate,
    GetClientCertificate returns the same material while it is live, and it is gone once deleted."""
    apigw = ctx.client("apigateway")

    description = ctx.unique_name("sim2real-apigw-cert-")
    created = apigw.generate_client_certificate(
        description=description, tags={"sim2real": "client-certificate-expiration-tracked"}
    )
    cert_id = created["clientCertificateId"]
    cleanup_state = {"deleted": False}

    def _cleanup():
        if not cleanup_state["deleted"]:
            apigw.delete_client_certificate(clientCertificateId=cert_id)

    ctx.on_cleanup(_cleanup)

    pem = created["pemEncodedCertificate"]
    assert pem.strip().startswith("-----BEGIN CERTIFICATE-----")
    assert pem.strip().endswith("-----END CERTIFICATE-----")

    created_date = created["createdDate"]
    expiration_date = created["expirationDate"]
    delta_days = (expiration_date - created_date).days
    assert delta_days == 365, f"expected a 365-day validity window, got {delta_days} days"

    # GetClientCertificate must return the exact same persisted material.
    fetched = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert fetched["pemEncodedCertificate"] == pem
    assert fetched["createdDate"] == created_date
    assert fetched["expirationDate"] == expiration_date
    assert fetched["description"] == description

    # Delete it, then confirm it is really gone (not merely marked inactive).
    apigw.delete_client_certificate(clientCertificateId=cert_id)
    cleanup_state["deleted"] = True

    code, message = _error(lambda: apigw.get_client_certificate(clientCertificateId=cert_id))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "Invalid client certificate id specified", f"unexpected message {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
