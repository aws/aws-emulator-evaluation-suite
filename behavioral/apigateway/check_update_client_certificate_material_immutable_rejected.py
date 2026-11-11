"""update-client-certificate-material-immutable-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-client-certificate-material-immutable-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateClientCertificate rejects patching the certificate material; /description still patches normally."""
    apigw = ctx.client("apigateway")

    created = apigw.generate_client_certificate(
        description="initial description",
        tags={"sim2real": "update-client-certificate-material-immutable-rejected"},
    )
    cert_id = created["clientCertificateId"]
    ctx.on_cleanup(lambda: apigw.delete_client_certificate(clientCertificateId=cert_id))
    original_pem = created["pemEncodedCertificate"]

    # Positive control: /description is a supported patch path.
    control = apigw.update_client_certificate(
        clientCertificateId=cert_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "control description"}],
    )
    assert control["description"] == "control description", (
        f"expected the positive control to apply, got {control['description']!r}"
    )

    # Negative: /pemEncodedCertificate is not a supported patch path.
    err = _client_error(
        lambda: apigw.update_client_certificate(
            clientCertificateId=cert_id,
            patchOperations=[{"op": "replace", "path": "/pemEncodedCertificate", "value": "bogus-cert-material"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    expected_message = (
        "Invalid patch path  '/pemEncodedCertificate' specified for op 'replace'. Must be one of: [/description]"
    )
    assert err.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {err.get('Message')!r}"
    )

    fetched = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert fetched["pemEncodedCertificate"] == original_pem, "rejected patch must not have mutated certificate material"
    assert fetched["description"] == "control description", "the prior valid description update must remain intact"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
