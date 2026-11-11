"""cancel-certificate-transfer-not-in-progress-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-certificate-transfer-not-in-progress-fails"
GROUP = 'overly-permissive'
SERVICES = ['iot']

# TransferCertificate does not verify the destination account exists, so a well-formed fake id
# puts a certificate into PENDING_TRANSFER for the positive control.
_FOREIGN_ACCOUNT = "111122223333"


def _err(fn):
    """The (code, message) fn() raises; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected CancelCertificateTransfer to be rejected, but it SUCCEEDED and returned {result!r}"
    )

def _delete_certificate(iot, cert_id):
    """Teardown: reclaim a pending outgoing transfer, detach policies/things,
    deactivate, then force-delete a certificate; a missing certificate is clean."""
    try:
        iot.cancel_certificate_transfer(certificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        cert_arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"
        ]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        cert_arn = None
    if cert_arn:
        try:
            for p in iot.list_attached_policies(target=cert_arn).get("policies", []):
                iot.detach_policy(policyName=p["policyName"], target=cert_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            for t in iot.list_principal_things(principal=cert_arn).get("things", []):
                try:
                    iot.detach_thing_principal(thingName=t, principal=cert_arn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelCertificateTransfer on a never-transferred certificate is rejected ResourceNotFound
    and leaves it ACTIVE, while cancelling a real pending transfer succeeds.
    """
    iot = ctx.client("iot")

    # Positive control: transfer a certificate for real, then cancel that real transfer.
    control = iot.create_keys_and_certificate(setAsActive=True)
    control_id = control["certificateId"]
    ctx.on_cleanup(lambda _n=control_id: _delete_certificate(iot, _n))
    iot.update_certificate(certificateId=control_id, newStatus="INACTIVE")
    iot.transfer_certificate(certificateId=control_id, targetAwsAccount=_FOREIGN_ACCOUNT)

    # DescribeCertificate 404s on the source while the transfer is pending; use the outgoing list.
    outgoing = {
        c["certificateId"] for c in iot.list_outgoing_certificates().get("outgoingCertificates", [])
    }
    assert control_id in outgoing, (
        f"positive control: TransferCertificate did not create a pending outgoing transfer "
        f"for {control_id!r}: {outgoing!r}"
    )

    iot.cancel_certificate_transfer(certificateId=control_id)

    # Cancelling restores source-account ownership: DescribeCertificate works again and the
    # certificate is gone from the outgoing list.
    cancelled = iot.describe_certificate(certificateId=control_id)["certificateDescription"]
    assert cancelled["status"] == "INACTIVE", (
        f"positive control: cancelling a real pending transfer must return the certificate "
        f"to INACTIVE and restore source-account visibility, got {cancelled['status']!r}"
    )
    outgoing_after = {
        c["certificateId"] for c in iot.list_outgoing_certificates().get("outgoingCertificates", [])
    }
    assert control_id not in outgoing_after, (
        f"positive control: {control_id!r} is still listed as an outgoing transfer after "
        f"cancellation: {outgoing_after!r}"
    )

    # Subject under test: a certificate that has never been transferred.
    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    code = _err(lambda: iot.cancel_certificate_transfer(certificateId=cert_id))
    assert code == ("ResourceNotFoundException", f"CertificateId {cert_id} does not exist"), (
        f"expected ResourceNotFoundException (no pending transfer record exists), got {code!r}"
    )

    # The certificate must be untouched by the rejected cancellation.
    desc = iot.describe_certificate(certificateId=cert_id)
    assert desc["certificateDescription"]["status"] == "ACTIVE", (
        f"a rejected CancelCertificateTransfer must not change the certificate's status, "
        f"got {desc['certificateDescription']['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
