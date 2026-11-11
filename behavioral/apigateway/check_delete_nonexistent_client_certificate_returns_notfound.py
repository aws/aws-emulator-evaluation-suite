"""delete-nonexistent-client-certificate-returns-notfound."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-nonexistent-client-certificate-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteClientCertificate on an id that no longer exists fails with NotFoundException, after the same
    freshly generated certificate deleted cleanly the first time."""
    apigw = ctx.client("apigateway")

    cert = apigw.generate_client_certificate(description=ctx.unique_name("sim2real-cc-"))
    cert_id = cert["clientCertificateId"]

    # positive control: the certificate really exists and the first delete succeeds
    apigw.get_client_certificate(clientCertificateId=cert_id)
    apigw.delete_client_certificate(clientCertificateId=cert_id)

    # negative: it is now gone, so a repeat delete is NotFoundException
    code, message = _client_error(lambda: apigw.delete_client_certificate(clientCertificateId=cert_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid client certificate id specified", message

    # and it truly is gone (not merely soft-deleted / still readable)
    get_code, get_message = _client_error(lambda: apigw.get_client_certificate(clientCertificateId=cert_id))
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code}"
    assert get_message == "Invalid client certificate id specified", get_message


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected success raises,
    so an accepted call is reported as accepted rather than as a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
