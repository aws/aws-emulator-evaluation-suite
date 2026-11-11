"""client-certificate-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "client-certificate-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GenerateClientCertificate -> Get -> Update -> Delete -> subsequent get returns not-found."""
    apigw = ctx.client("apigateway")

    created = apigw.generate_client_certificate(
        description="sim2real initial description",
        tags={"sim2real": "client-certificate-lifecycle"},
    )
    cert_id = created["clientCertificateId"]
    ctx.on_cleanup(lambda: _safe_delete_cert(apigw, cert_id))
    assert created["description"] == "sim2real initial description", (
        f"expected the generate response to echo the description, got {created['description']!r}"
    )
    assert created["pemEncodedCertificate"], "expected a non-empty PEM certificate from generate"

    got = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert got["clientCertificateId"] == cert_id, (
        f"expected get to return the same id {cert_id!r}, got {got['clientCertificateId']!r}"
    )
    assert got["pemEncodedCertificate"] == created["pemEncodedCertificate"], (
        "expected get to return the same PEM material generate returned"
    )

    updated = apigw.update_client_certificate(
        clientCertificateId=cert_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "sim2real updated description"}],
    )
    assert updated["description"] == "sim2real updated description", (
        f"expected update response description to reflect the patch, got {updated['description']!r}"
    )
    assert updated["pemEncodedCertificate"] == created["pemEncodedCertificate"], (
        "certificate material must be immutable across an UpdateClientCertificate description patch"
    )
    got_after_update = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert got_after_update["description"] == "sim2real updated description", (
        f"expected get after update to reflect the new description, got {got_after_update['description']!r}"
    )
    assert got_after_update["pemEncodedCertificate"] == created["pemEncodedCertificate"], (
        "certificate material must still be immutable when read back after the patch"
    )

    apigw.delete_client_certificate(clientCertificateId=cert_id)
    code, message = _error(lambda: apigw.get_client_certificate(clientCertificateId=cert_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException reading a deleted client certificate, got {code!r}"
    )
    assert message == "Invalid client certificate id specified", f"unexpected message {message!r}"


def _error(fn):
    """Call fn(); return botocore Error.Code if a ClientError is raised. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_cert(apigw, cert_id: str) -> None:
    try:
        apigw.delete_client_certificate(clientCertificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
