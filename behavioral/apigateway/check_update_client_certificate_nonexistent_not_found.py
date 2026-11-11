"""update-client-certificate-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-client-certificate-nonexistent-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _client_error(fn):
    """Call fn(); return its botocore Error dict if a ClientError is raised.

    An unexpected SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is
    the strongest signal available and must not be reported as an error-code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_errors(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateClientCertificate applies a patch to a real client certificate (positive control, read
    back independently) and fails with NotFoundException for an unknown clientCertificateId."""
    ag = ctx.client("apigateway")

    created = ag.generate_client_certificate(description=ctx.unique_name("sim2real-cc-"))
    cert_id = created["clientCertificateId"]
    ctx.on_cleanup(lambda: _ignore_errors(lambda: ag.delete_client_certificate(clientCertificateId=cert_id)))

    updated = ag.update_client_certificate(
        clientCertificateId=cert_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "sim2real-behav-updated"}],
    )
    assert updated["description"] == "sim2real-behav-updated"
    fetched = ag.get_client_certificate(clientCertificateId=cert_id)
    assert fetched["description"] == "sim2real-behav-updated", (
        "positive control failed: UpdateClientCertificate did not take effect on a real certificate"
    )

    bogus_id = ctx.unique_name("sim2real-behav-no-such-cert-")
    err = _client_error(
        lambda: ag.update_client_certificate(
            clientCertificateId=bogus_id,
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert err.get("Code") == "NotFoundException", (
        f"expected NotFoundException updating a nonexistent client certificate, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "Invalid client certificate id specified", (
        f"expected the exact unknown-certificate message from UpdateClientCertificate, got {err.get('Message')!r}"
    )

    # and that id truly never existed -- not merely a validation quirk on the id shape
    get_err = _client_error(lambda: ag.get_client_certificate(clientCertificateId=bogus_id))
    assert get_err.get("Code") == "NotFoundException", (
        f"expected the nonexistent clientCertificateId to also read as NotFoundException, got {get_err.get('Code')!r}"
    )
    assert get_err.get("Message") == "Invalid client certificate id specified", (
        f"expected the exact unknown-certificate message from GetClientCertificate, got {get_err.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
