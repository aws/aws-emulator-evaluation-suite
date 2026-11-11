"""audit-suppression-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "audit-suppression-lifecycle"
GROUP = 'audit'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAuditSuppression -> Describe -> Update -> List -> Delete for a real certificate."""
    iot = ctx.client("iot")
    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    check_name = "DEVICE_CERTIFICATE_EXPIRING_CHECK"
    resource_id = {"deviceCertificateId": cert_id}

    iot.create_audit_suppression(
        checkName=check_name,
        resourceIdentifier=resource_id,
        clientRequestToken=ctx.unique_name("crt-"),
        suppressIndefinitely=True,
        description="probe suppression",
    )
    ctx.on_cleanup(
        lambda _c=check_name, _r=resource_id: iot.delete_audit_suppression(
            checkName=_c, resourceIdentifier=_r
        )
    )

    desc = iot.describe_audit_suppression(
        checkName=check_name, resourceIdentifier=resource_id
    )
    assert desc["checkName"] == check_name, f"expected checkName {check_name!r}, got {desc['checkName']!r}"
    assert desc["suppressIndefinitely"] is True, f"expected suppressIndefinitely True, got {desc['suppressIndefinitely']!r}"
    assert desc["description"] == "probe suppression", f"expected description 'probe suppression', got {desc['description']!r}"

    iot.update_audit_suppression(
        checkName=check_name,
        resourceIdentifier=resource_id,
        suppressIndefinitely=True,
        description="updated suppression",
    )
    desc2 = iot.describe_audit_suppression(
        checkName=check_name, resourceIdentifier=resource_id
    )
    assert desc2["description"] == "updated suppression", desc2["description"]

    listed = iot.list_audit_suppressions().get("suppressions", [])
    assert any(
        s.get("resourceIdentifier", {}).get("deviceCertificateId") == cert_id for s in listed
    ), "created suppression missing from ListAuditSuppressions"

    iot.delete_audit_suppression(checkName=check_name, resourceIdentifier=resource_id)
    missing = (
        f"Audit Suppression with CheckName={check_name} and "
        f'ResourceIdentifier={{"deviceCertificateId":"{cert_id}"}} does not exist'
    )
    code = _err(
        lambda: iot.describe_audit_suppression(
            checkName=check_name, resourceIdentifier=resource_id
        )
    )
    assert code == ("ResourceNotFoundException", missing), (
        f"expected ResourceNotFoundException for the deleted suppression, got {code!r}"
    )

    update_code = _err(
        lambda: iot.update_audit_suppression(
            checkName=check_name,
            resourceIdentifier=resource_id,
            suppressIndefinitely=True,
            description="post-delete mutation",
        )
    )
    assert update_code == ("ResourceNotFoundException", missing), (
        f"expected UpdateAuditSuppression on a deleted suppression to fail with "
        f"ResourceNotFoundException, got {update_code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
