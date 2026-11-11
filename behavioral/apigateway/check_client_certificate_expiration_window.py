"""client-certificate-expiration-window."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "client-certificate-expiration-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GenerateClientCertificate issues a fixed ~365-day validity window,
    consistently reported by both GetClientCertificate and GetClientCertificates.
    """
    apigw = ctx.client("apigateway")

    created = apigw.generate_client_certificate(
        description=ctx.unique_name("sim2real-behav-cert-"),
        tags={"sim2real": "client-certificate-expiration-window"},
    )
    cert_id = created["clientCertificateId"]
    ctx.on_cleanup(lambda: apigw.delete_client_certificate(clientCertificateId=cert_id))

    created_date = created["createdDate"]
    expiration_date = created["expirationDate"]
    assert expiration_date > created_date

    validity_days = (expiration_date - created_date).days
    assert validity_days == 365, f"expected exactly a 365-day validity window, got {validity_days} days"

    got = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert got["createdDate"] == created_date
    assert got["expirationDate"] == expiration_date

    listed = [
        item
        for page in apigw.get_paginator("get_client_certificates").paginate()
        for item in page["items"]
    ]
    match = next((item for item in listed if item["clientCertificateId"] == cert_id), None)
    assert match is not None, "generated certificate missing from GetClientCertificates listing"
    assert match["createdDate"] == created_date
    assert match["expirationDate"] == expiration_date


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
