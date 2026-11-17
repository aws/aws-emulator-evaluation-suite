"""update-certificate-internal-statuses-refused-register-inactive-round-trips."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-certificate-internal-statuses-refused-register-inactive-round-trips"
GROUP = "certificate-lifecycle"
SERVICES = ["iot"]


def expect_error(fn, code, message):
    """Assert fn() raises exactly (code, message); an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_code, got_message = err.get("Code"), err.get("Message")
        assert got_code == code, f"expected error code {code!r}, got {got_code!r} ({got_message!r})"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected {code!r}, but the call succeeded and returned {result!r}")


def _delete_certificate(iot, cert_id):
    """Cleanup: set INACTIVE, since an ACTIVE certificate cannot be deleted, then delete with
    forceDelete; ResourceNotFoundException means it is already gone."""
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _status(iot, cert_id):
    return iot.describe_certificate(certificateId=cert_id)["certificateDescription"]["status"]


_PENDING_ACTIVATION_REFUSED = (
    "CertificateStateException",
    "Not allowed to update to PENDING_ACTIVATION status using UpdateCertificate call",
)
_PENDING_TRANSFER_REFUSED = (
    "CertificateStateException",
    "Not allowed to update to PENDING_TRANSFER status using UpdateCertificate call",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCertificate refuses PENDING_ACTIVATION and PENDING_TRANSFER on an ACTIVE
    certificate, each leaving it ACTIVE, while REGISTER_INACTIVE round-trips back to
    ACTIVE and INACTIVE is settable, each confirmed by DescribeCertificate."""
    iot = ctx.client("iot")
    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    assert _status(iot, cert_id) == "ACTIVE", (
        f"expected ACTIVE right after create(setAsActive=True), got {_status(iot, cert_id)!r}"
    )

    expect_error(
        lambda: iot.update_certificate(certificateId=cert_id, newStatus="PENDING_ACTIVATION"),
        *_PENDING_ACTIVATION_REFUSED,
    )
    assert _status(iot, cert_id) == "ACTIVE", (
        f"a refused PENDING_ACTIVATION transition must leave the certificate ACTIVE, "
        f"got {_status(iot, cert_id)!r}"
    )

    expect_error(
        lambda: iot.update_certificate(certificateId=cert_id, newStatus="PENDING_TRANSFER"),
        *_PENDING_TRANSFER_REFUSED,
    )
    assert _status(iot, cert_id) == "ACTIVE", (
        f"a refused PENDING_TRANSFER transition must leave the certificate ACTIVE, "
        f"got {_status(iot, cert_id)!r}"
    )

    # REGISTER_INACTIVE is caller-settable through UpdateCertificate, and reversible.
    iot.update_certificate(certificateId=cert_id, newStatus="REGISTER_INACTIVE")
    assert _status(iot, cert_id) == "REGISTER_INACTIVE", (
        f"expected REGISTER_INACTIVE after UpdateCertificate(newStatus=REGISTER_INACTIVE), "
        f"got {_status(iot, cert_id)!r}"
    )

    iot.update_certificate(certificateId=cert_id, newStatus="ACTIVE")
    assert _status(iot, cert_id) == "ACTIVE", (
        f"expected ACTIVE after round-tripping REGISTER_INACTIVE back to ACTIVE, "
        f"got {_status(iot, cert_id)!r}"
    )

    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    assert _status(iot, cert_id) == "INACTIVE", (
        f"expected INACTIVE after UpdateCertificate(newStatus=INACTIVE), got {_status(iot, cert_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
