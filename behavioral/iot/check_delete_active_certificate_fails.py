"""delete-active-certificate-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-active-certificate-fails"
GROUP = 'certificate-lifecycle'
SERVICES = ['iot']

def _error(fn):
    """Call fn(); return the botocore (error code, message) if a ClientError is raised. Raises if fn()
    unexpectedly succeeds, so an accepted call fails clearly as an acceptance."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")

def _delete_certificate(iot, cert_id):
    """Teardown: detach policies/things, deactivate, then force-delete; a missing certificate is clean."""
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
    """DeleteCertificate on an ACTIVE certificate must fail; only INACTIVE certs can be deleted."""
    iot = ctx.client("iot")
    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    err = _error(lambda: iot.delete_certificate(certificateId=cert_id))
    assert err == ("CertificateStateException", f"Certificate must be deactivated (not ACTIVE) before deletion. Id: {cert_id}"), err

    # still present and still ACTIVE
    desc = iot.describe_certificate(certificateId=cert_id)
    assert desc["certificateDescription"]["status"] == "ACTIVE"

    # after deactivating, deletion succeeds
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_certificate(certificateId=cert_id)
    not_found = _error(lambda: iot.describe_certificate(certificateId=cert_id))
    assert not_found == ("ResourceNotFoundException", f"CertificateId {cert_id} does not exist"), not_found

    # a mutation on the now-dead id also fails, not just the read
    mutate_not_found = _error(
        lambda: iot.update_certificate(certificateId=cert_id, newStatus="ACTIVE")
    )
    assert mutate_not_found == ("ResourceNotFoundException", f"CertificateId {cert_id} does not exist"), mutate_not_found


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
