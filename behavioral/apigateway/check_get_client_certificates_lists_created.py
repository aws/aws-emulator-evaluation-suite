"""get-client-certificates-lists-created."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-client-certificates-lists-created"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetClientCertificates includes a generated certificate in its collection, and excludes it
    (with the certificate itself now unreadable and unmutable) once deleted."""
    apigw = ctx.client("apigateway")

    created = apigw.generate_client_certificate(
        description="sim2real listing check", tags={"sim2real": CHECK}
    )
    cert_id = created["clientCertificateId"]
    ctx.on_cleanup(lambda: _safe_delete_cert(apigw, cert_id))

    def _list_page(position):
        return apigw.get_client_certificates(**({"position": position} if position else {}))

    found = _find_in_paginated(
        _list_page,
        item_key="items",
        matches=lambda item: item.get("clientCertificateId") == cert_id,
        timeout_s=60,
    )
    assert found is not None, f"client certificate {cert_id} not present in GetClientCertificates"
    assert found["description"] == "sim2real listing check", (
        f"expected description 'sim2real listing check', got {found.get('description')!r}"
    )

    apigw.delete_client_certificate(clientCertificateId=cert_id)

    still_listed = _find_in_paginated(
        _list_page,
        item_key="items",
        matches=lambda item: item.get("clientCertificateId") == cert_id,
        timeout_s=60,
    )
    assert still_listed is None, (
        f"deleted client certificate {cert_id} still present in GetClientCertificates"
    )

    get_code, get_message = _error(lambda: apigw.get_client_certificate(clientCertificateId=cert_id))
    assert get_code == "NotFoundException", (
        f"expected NotFoundException reading deleted certificate, got {get_code}"
    )
    assert get_message == "Invalid client certificate id specified", (
        f"unexpected NotFoundException message {get_message!r}"
    )

    update_code, update_message = _error(
        lambda: apigw.update_client_certificate(
            clientCertificateId=cert_id,
            patchOperations=[{"op": "replace", "path": "/description", "value": "should not apply"}],
        )
    )
    assert update_code == "NotFoundException", (
        f"expected NotFoundException updating deleted certificate, got {update_code}"
    )
    assert update_message == "Invalid client certificate id specified", (
        f"unexpected NotFoundException message {update_message!r}"
    )


def _find_in_paginated(page_fn, *, item_key, matches, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    position = None
    while True:
        page = page_fn(position)
        for item in page.get(item_key, []):
            if matches(item):
                return item
        position = page.get("position")
        if not position or time.monotonic() >= deadline:
            return None


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {result!r}")


def _safe_delete_cert(apigw, cert_id: str) -> None:
    try:
        apigw.delete_client_certificate(clientCertificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
