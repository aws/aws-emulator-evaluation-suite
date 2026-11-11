"""certificate-state-transitions."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "certificate-state-transitions"
GROUP = 'certificate-lifecycle'
SERVICES = ['iot']

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Certificate state machine: ACTIVE (on create) -> INACTIVE -> REVOKED, each reflected in describe."""
    iot = ctx.client("iot")
    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    desc = iot.describe_certificate(certificateId=cert_id)
    status = desc["certificateDescription"]["status"]
    assert status == "ACTIVE", f"expected ACTIVE after create(setAsActive=True), got {status}"

    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    desc = iot.describe_certificate(certificateId=cert_id)
    status = desc["certificateDescription"]["status"]
    assert status == "INACTIVE", f"expected INACTIVE after UpdateCertificate(INACTIVE), got {status}"

    iot.update_certificate(certificateId=cert_id, newStatus="REVOKED")
    desc = iot.describe_certificate(certificateId=cert_id)
    status = desc["certificateDescription"]["status"]
    assert status == "REVOKED", f"expected REVOKED after UpdateCertificate(REVOKED), got {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
