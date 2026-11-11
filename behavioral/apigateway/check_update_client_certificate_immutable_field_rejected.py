"""update-client-certificate-immutable-field-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-client-certificate-immutable-field-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateClientCertificate rejects patching /pemEncodedCertificate and leaves the cert unchanged.
    Patching /description on the same certificate still succeeds (positive control)."""
    apigw = ctx.client("apigateway")

    created = apigw.generate_client_certificate(description="original description")
    cert_id = created["clientCertificateId"]
    ctx.on_cleanup(lambda: _ignore_errors(lambda: apigw.delete_client_certificate(clientCertificateId=cert_id)))
    original_pem = created["pemEncodedCertificate"]

    err = _client_error(
        lambda: apigw.update_client_certificate(
            clientCertificateId=cert_id,
            patchOperations=[
                {"op": "replace", "path": "/pemEncodedCertificate", "value": "-----BEGIN CERTIFICATE-----\nbogus\n-----END CERTIFICATE-----"}
            ],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    expected_message = (
        "Invalid patch path  '/pemEncodedCertificate' specified for op 'replace'. Must be one of: [/description]"
    )
    assert err.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {err.get('Message')!r}"
    )

    # The forbidden mutation did not happen: certificate material and description are unchanged.
    unchanged = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert unchanged["pemEncodedCertificate"] == original_pem, (
        f"expected certificate material unchanged after rejected patch, got {unchanged['pemEncodedCertificate']!r}"
    )
    assert unchanged["description"] == "original description", (
        f"expected description unchanged after rejected patch, got {unchanged['description']!r}"
    )

    # Positive control: /description is the one patchable field.
    updated = apigw.update_client_certificate(
        clientCertificateId=cert_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "legit update"}],
    )
    assert updated["description"] == "legit update", f"expected 'legit update', got {updated['description']!r}"
    assert updated["pemEncodedCertificate"] == original_pem, (
        f"expected certificate material unchanged by description patch, got {updated['pemEncodedCertificate']!r}"
    )

    final = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert final["description"] == "legit update", f"expected 'legit update' on independent read, got {final['description']!r}"
    assert final["pemEncodedCertificate"] == original_pem, (
        f"expected certificate material unchanged on independent read, got {final['pemEncodedCertificate']!r}"
    )


def _client_error(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_errors(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
