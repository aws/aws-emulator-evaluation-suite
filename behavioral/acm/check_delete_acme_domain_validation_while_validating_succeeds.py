"""delete-acme-domain-validation-while-validating-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-acme-domain-validation-while-validating-succeeds"
GROUP = "overly-permissive"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAcmeDomainValidation is not gated on validation work: deleting a live domain
    validation succeeds, both with no DNS work and with a server-managed DNS challenge record
    in an owned hosted zone, and Describe then raises ResourceNotFoundException for each."""
    acm = ctx.client("acm")
    route53 = ctx.client("route53")
    endpoint_arn = _create_active_endpoint(ctx, acm)

    # First leg: DeleteAcmeDomainValidation on a manual/out-of-band domain validation
    # succeeds right after create, whichever live status ACM has reached.
    control_domain = f"{ctx.unique_name('sim2real-acmedv-ctl-').lower()}.example.com"
    control_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=control_domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )["AcmeDomainValidationArn"]
    control_before = acm.describe_acme_domain_validation(AcmeDomainValidationArn=control_arn)[
        "AcmeDomainValidation"
    ]
    assert control_before["Status"] in _LIVE_STATUSES, (
        f"control domain validation not live after create: {control_before['Status']!r}"
    )
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=control_arn)
    control_code, control_message = _poll_for_gone(
        lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=control_arn)
    )
    assert control_code == "ResourceNotFoundException", (
        f"control delete-while-VALIDATING did not remove the resource: "
        f"describe afterwards returned {control_code!r} instead of ResourceNotFoundException"
    )
    assert control_message == f"Could not find ACME domain validation {control_arn}.", control_message

    # Target: a domain validation whose DNS prevalidation names a real, owned Route 53
    # hosted zone -- ACM computes and writes a challenge CNAME into it and actively polls
    # that zone. This is the strongest "in-flight validation work" this API can produce
    # without a genuine external ACME client, and delete is still not blocked by it.
    domain_name, hosted_zone_id = _create_hosted_zone(ctx, route53)
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={
            "DnsPrevalidation": {
                "DomainScope": {"ExactDomain": "ENABLED"},
                "HostedZoneId": hosted_zone_id,
            }
        },
    )["AcmeDomainValidationArn"]
    dv_deleted = {"done": False}
    ctx.on_cleanup(lambda: _cleanup_target_dv(acm, dv_arn, dv_deleted))

    record = _wait_for_resource_record(acm, dv_arn)
    assert record.get("Name") and record.get("Value"), (
        f"server-managed DNS challenge record never materialized for {dv_arn}: {record!r}"
    )

    before = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert before["Status"] in _LIVE_STATUSES, (
        f"target domain validation not live with its DNS record written: "
        f"{before['Status']!r}"
    )

    code, _message = _error(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))
    if code == _SUCCEEDED:
        dv_deleted["done"] = True
    assert code == _SUCCEEDED, (
        f"delete of a live domain validation succeeds even with a server-managed "
        f"DNS record written; "
        f"got unexpected error {code!r} instead"
    )

    gone_code, gone_message = _poll_for_gone(
        lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"delete of the server-managed domain validation did not remove it: "
        f"describe afterwards returned {gone_code!r} instead of ResourceNotFoundException"
    )
    assert gone_message == f"Could not find ACME domain validation {dv_arn}.", gone_message


_SUCCEEDED = "SUCCEEDED"


def _error(fn):
    """The (code, message) of the ClientError fn raises, or (_SUCCEEDED, None) when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED, None


def _poll_for_gone(fn, timeout_s=60.0, interval_s=2.0):
    """Deletion is not instantaneous -- a Describe right after Delete can still catch
    a transitional DELETING record. Poll until the resource is actually gone rather
    than trusting a single read (time is two-sided)."""
    deadline = time.monotonic() + timeout_s
    outcome = (None, None)
    while time.monotonic() < deadline:
        outcome = _error(fn)
        if outcome[0] == "ResourceNotFoundException":
            return outcome
        time.sleep(interval_s)
    return outcome


def _wait_endpoint_active(acm, arn, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError("ACME endpoint creation failed")
        time.sleep(interval_s)
    raise AssertionError("ACME endpoint never became ACTIVE within timeout")


def _create_active_endpoint(ctx, acm):
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_quiet(acm, arn))
    _wait_endpoint_active(acm, arn)
    return arn


def _delete_endpoint_quiet(acm, endpoint_arn):
    for attempt in range(10):
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and attempt < 9:
                time.sleep(3)
                continue
            raise


def _create_hosted_zone(ctx, route53):
    """A real, owned Route 53 hosted zone gives ACM somewhere to write and poll the
    DNS challenge CNAME -- without one, prevalidation stays purely manual/out-of-band
    and never has genuine work in flight for ACM to protect with a delete conflict."""
    zone_name = f"{ctx.unique_name('sim2real-acmedv-').lower()}.com"
    resp = route53.create_hosted_zone(
        Name=zone_name,
        CallerReference=ctx.unique_name("sim2real-acmedv-zone-"),
    )
    zone_id = resp["HostedZone"]["Id"].split("/")[-1]
    try:
        route53.change_tags_for_resource(
            ResourceType="hostedzone",
            ResourceId=zone_id,
            AddTags=[{"Key": "Name", "Value": zone_name}],
        )
    except ClientError:
        pass
    ctx.on_cleanup(lambda: _delete_hosted_zone_quiet(route53, zone_id))
    return zone_name.rstrip("."), zone_id


def _delete_hosted_zone_quiet(route53, zone_id):
    try:
        record_sets = route53.list_resource_record_sets(HostedZoneId=zone_id)["ResourceRecordSets"]
        changes = [
            {"Action": "DELETE", "ResourceRecordSet": rs}
            for rs in record_sets
            if rs["Type"] not in ("NS", "SOA")
        ]
        if changes:
            route53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch={"Changes": changes})
        route53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHealthCheck",
            "NoSuchHostedZone",
        ):
            raise


def _cleanup_target_dv(acm, dv_arn, dv_deleted):
    if dv_deleted["done"]:
        return
    for attempt in range(10):
        try:
            acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and attempt < 9:
                time.sleep(3)
                continue
            raise


def _wait_for_resource_record(acm, dv_arn, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
        record = last.get("PrevalidationDetails", {}).get("DnsPrevalidation", {}).get("ResourceRecord")
        if record:
            return record
        time.sleep(interval_s)
    raise AssertionError(f"ResourceRecord never materialized for {dv_arn} within {timeout_s}s, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
