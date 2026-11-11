"""delete-certificate-with-attached-thing-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-certificate-with-attached-thing-fails"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _delete_once_detached(iot, cert_id, timeout_s: float = 30.0, interval_s: float = 2.0):
    """DeleteCertificate, retrying only while the thing detachment is still propagating
    (DeleteConflictException); any other error, or the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iot.delete_certificate(certificateId=cert_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DeleteConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)

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
    """DeleteCertificate (even inactive) with an attached thing must fail with DeleteConflictException unless forceDelete=True."""
    iot = ctx.client("iot")
    thing_name = ctx.unique_name("sim2real-behav-thing-certdel-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda _n=thing_name: iot.delete_thing(thingName=_n))

    resp = iot.create_keys_and_certificate(setAsActive=False)
    cert_id = resp["certificateId"]
    cert_arn = resp["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)

    err = _error(lambda: iot.delete_certificate(certificateId=cert_id))
    assert err == ("DeleteConflictException", f"Things must be detached before deletion (arn: {cert_arn})"), err

    # Real AWS does NOT let forceDelete bypass a *thing* attachment -- forceDelete
    # only overrides ACTIVE status / policy attachments. The thing must be detached.
    err_forced = _error(
        lambda: iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    )
    assert err_forced == ("DeleteConflictException", f"Things must be detached before deletion (arn: {cert_arn})"), (
        f"forceDelete must still conflict while a thing is attached, got {err_forced!r}"
    )

    # Detaching the thing is the only way through.
    iot.detach_thing_principal(thingName=thing_name, principal=cert_arn)

    _delete_once_detached(iot, cert_id)

    err2 = _error(lambda: iot.describe_certificate(certificateId=cert_id))
    assert err2 == ("ResourceNotFoundException", f"CertificateId {cert_id} does not exist"), err2

    # a mutation on the dead id also fails, not just a read
    err3 = _error(lambda: iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE"))
    assert err3 == ("ResourceNotFoundException", f"CertificateId {cert_id} does not exist"), err3


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
