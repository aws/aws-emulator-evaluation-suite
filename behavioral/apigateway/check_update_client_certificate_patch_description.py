"""update-client-certificate-patch-description."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-client-certificate-patch-description"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateClientCertificate patches description while certificate material is immutable;
    deleting the certificate afterward leaves it genuinely gone, not merely soft-deleted."""
    apigw = ctx.client("apigateway")

    created = apigw.generate_client_certificate(description="initial description", tags={"sim2real": CHECK})
    cert_id = created["clientCertificateId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_client_certificate(clientCertificateId=cert_id)))
    original_pem = created["pemEncodedCertificate"]
    assert created["description"] == "initial description", (
        f"expected initial description, got {created['description']!r}"
    )

    updated = apigw.update_client_certificate(
        clientCertificateId=cert_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "updated description"}],
    )
    assert updated["description"] == "updated description", (
        f"expected patched description in the update response, got {updated['description']!r}"
    )
    assert updated["pemEncodedCertificate"] == original_pem, "certificate material must be immutable"

    fetched = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert fetched["description"] == "updated description", (
        f"expected independent read to reflect the patched description, got {fetched['description']!r}"
    )
    assert fetched["pemEncodedCertificate"] == original_pem, (
        "independent read must show unchanged certificate material"
    )

    # The cleanup delete is a free negative assertion: prove the certificate is genuinely
    # gone (not merely soft-deleted) and that a further mutation on the dead id also fails.
    apigw.delete_client_certificate(clientCertificateId=cert_id)
    get_err = _client_error(lambda: apigw.get_client_certificate(clientCertificateId=cert_id))
    assert get_err.get("Code") == "NotFoundException", (
        f"expected NotFoundException on deleted cert, got {get_err.get('Code')!r}"
    )
    assert get_err.get("Message") == "Invalid client certificate id specified", (
        f"expected the exact deleted-certificate message from GetClientCertificate, got {get_err.get('Message')!r}"
    )
    update_err = _client_error(
        lambda: apigw.update_client_certificate(
            clientCertificateId=cert_id,
            patchOperations=[{"op": "replace", "path": "/description", "value": "post-delete"}],
        )
    )
    assert update_err.get("Code") == "NotFoundException", (
        f"expected update on a deleted cert to fail NotFoundException, got {update_err.get('Code')!r}"
    )
    assert update_err.get("Message") == "Invalid client certificate id specified", (
        f"expected the exact deleted-certificate message from UpdateClientCertificate, got {update_err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
