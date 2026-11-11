"""dns-validation-withholds-issuance-when-the-zone-is-not-publicly-delegated."""
from __future__ import annotations

import datetime
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dns-validation-withholds-issuance-when-the-zone-is-not-publicly-delegated"
GROUP = "state-machine"
SERVICES = ["acm"]

_TOKEN_RE = re.compile(r"^_[0-9a-f]{16,64}$")

# The withheld-issuance window, read every 2 s.
_ABSENCE_WINDOW_S = 30.0

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
    "PriorRequestNotComplete",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on throttle codes."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on deadline (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _crypto():
    """Lazily import `cryptography`; ImportError propagates if it is absent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _self_signed(common_name):
    """A self-signed RSA-2048 leaf and its key, both PEM. Generated in-process; the key is not
    a credential and never leaves this process except into ImportCertificate."""
    x509, hashes, serialization, rsa, NameOID = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-acm-not-a-real-key"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def _validation_record(acm, arn):
    """The single DNS validation ResourceRecord ACM published, or None if not yet published."""
    detail = _retry_throttle(lambda: acm.describe_certificate(CertificateArn=arn))["Certificate"]
    options = detail["DomainValidationOptions"] if "DomainValidationOptions" in detail else []
    if len(options) != 1 or "ResourceRecord" not in options[0]:
        return None
    return detail, options[0]["ResourceRecord"]


def _record_sets(route53, zone_id):
    """Every record set in a hosted zone, following the paginated cursor."""
    sets, kwargs = [], {"HostedZoneId": zone_id}
    while True:
        page = _retry_throttle(
            lambda kw=dict(kwargs): route53.list_resource_record_sets(**kw))
        sets.extend(page["ResourceRecordSets"])
        if not page["IsTruncated"]:
            return sets
        kwargs["StartRecordName"] = page["NextRecordName"]
        kwargs["StartRecordType"] = page["NextRecordType"]


def _issued_arns(acm):
    """Every certificate ARN ACM currently reports as ISSUED, following the paginator."""
    arns = set()
    for page in acm.get_paginator("list_certificates").paginate(
            CertificateStatuses=["ISSUED"]):
        for summary in page["CertificateSummaryList"]:
            arns.add(summary["CertificateArn"])
    return arns


def _validation_statuses(acm, arn):
    """ListCertificateDomainValidations' per-domain status map, following NextToken."""
    statuses, token = {}, None
    while True:
        kwargs = {"CertificateArn": arn}
        if token:
            kwargs["NextToken"] = token
        page = _retry_throttle(
            lambda kw=dict(kwargs): acm.list_certificate_domain_validations(**kw))
        for summary in page["DomainValidationSummaryList"]:
            config = None
            for key in ("ActiveValidationConfiguration", "RequestedValidationConfiguration"):
                if key in summary and summary[key]:
                    config = summary[key]
                    break
            assert config is not None, (
                f"ListCertificateDomainValidations returned no validation configuration for "
                f"{summary['DomainName']!r}: {summary!r}"
            )
            statuses[summary["DomainName"]] = config["ValidationStatus"]
        token = page.get("NextToken")
        if not token:
            return statuses


def _safe_delete_certificate(acm, arn):
    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ACM withholds issuance when its validation CNAME sits in a Route 53 zone the TLD never
    delegated: the certificate stays PENDING_VALIDATION with an unchanged challenge for 30 s after
    an imported control reaches ISSUED, and is absent from ListCertificates(ISSUED).

    Reference: https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html
    """
    acm = ctx.client("acm")
    route53 = ctx.client("route53")

    # A random label under a real TLD. No account owns it, so no registrar delegates `.com` to
    # the zone created below -- that is the structural barrier, not a timing assumption. A reserved
    # name (`example.com`) would instead be failed with ADDITIONAL_VERIFICATION_REQUIRED.
    apex = f"s2rprobe{uuid.uuid4().hex[:12]}.com"

    zone = _retry_throttle(lambda: route53.create_hosted_zone(
        Name=apex,
        CallerReference=str(uuid.uuid4()),
        HostedZoneConfig={"Comment": f"sim2real {CHECK}", "PrivateZone": False},
    ))
    zone_id = zone["HostedZone"]["Id"]
    name_servers = zone["DelegationSet"]["NameServers"]
    assert name_servers, (
        f"a public hosted zone must come with a delegation set; Route 53 returned "
        f"{zone['DelegationSet']!r}"
    )

    def _delete_zone():
        try:
            route53.delete_hosted_zone(Id=zone_id)
        except ClientError as exc:
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("NoSuchHostedZone",):
                raise RuntimeError(f"hosted zone {zone_id} ({apex}) not deleted -- BILLED resource: "
                                   f"{exc.response['Error']['Code']}") from exc

    # Registered FIRST so it runs LAST: the record set must be gone before the zone can go.
    ctx.on_cleanup(_delete_zone)
    _retry_throttle(lambda: route53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=zone_id.rsplit("/", 1)[-1],
        AddTags=[{"Key": "sim2real", "Value": CHECK}]))

    # --- the subject: a DNS-validated certificate for that apex. ---
    cert_arn = _retry_throttle(lambda: acm.request_certificate(
        DomainName=apex,
        ValidationMethod="DNS",
        IdempotencyToken=uuid.uuid4().hex[:24],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete_certificate(acm, cert_arn))

    detail, record = _poll_until(
        ctx, lambda: _validation_record(acm, cert_arn),
        lambda pair: pair is not None,
        timeout_s=_budget_s(ctx, 180), interval_s=2,
        description=f"ACM publishing the DNS validation CNAME for {apex!r}",
    )
    assert detail["Status"] == "PENDING_VALIDATION", (
        f"the certificate must start out awaiting DNS proof; Status is {detail['Status']!r} "
        f"(FailureReason {detail.get('FailureReason')!r})"
    )
    assert record["Type"] == "CNAME", (
        f"ACM's DNS challenge must be a CNAME; got {record['Type']!r}")
    # The target is `_<token>.<label>.acm-validations.<domain>`; the domain is the target's own,
    # so the token, label and acm-validations are matched by position and the rest only has to
    # be a domain.
    target = record["Value"].rstrip(".").split(".")
    assert (len(target) > 3 and _TOKEN_RE.match(target[0]) is not None and target[1]
            and target[2] == "acm-validations" and all(target[3:])), (
        "the challenge target must be _<token>.<label>.acm-validations.<domain>; got "
        f"{record['Value']!r}")
    assert _TOKEN_RE.match(record["Name"].rstrip(".").split(".", 1)[0]) is not None, (
        f"the challenge name's leading label must be an underscore-prefixed token; got "
        f"{record['Name']!r}"
    )

    # --- publish EXACTLY what ACM asked for, into the zone this check owns. ---
    change = _retry_throttle(lambda: route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Comment": f"sim2real {CHECK}",
            "Changes": [{
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": record["Name"],
                    "Type": "CNAME",
                    "TTL": 60,
                    "ResourceRecords": [{"Value": record["Value"]}],
                },
            }],
        },
    ))["ChangeInfo"]

    def _delete_record():
        try:
            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Changes": [{
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        "Name": record["Name"], "Type": "CNAME", "TTL": 60,
                        "ResourceRecords": [{"Value": record["Value"]}],
                    },
                }]},
            )
        except ClientError as exc:
            # A record already gone answers InvalidChangeBatch; any other failure is reported.
            if exc.response["Error"]["Code"] != "InvalidChangeBatch":
                raise

    # Registered SECOND so it runs FIRST (LIFO), unblocking the zone delete.
    ctx.on_cleanup(_delete_record)

    _poll_until(
        ctx, lambda: _retry_throttle(
            lambda: route53.get_change(Id=change["Id"]))["ChangeInfo"]["Status"],
        lambda status: status == "INSYNC",
        timeout_s=_budget_s(ctx, 180), interval_s=1,
        description=(
            f"Route 53 propagating the validation CNAME to all {len(name_servers)} name "
            f"servers of zone {zone_id}"
        ),
    )

    # Independent read at Route 53: the record really is in the zone, with ACM's exact bytes.
    published = {
        (rrset["Name"].rstrip("."), rrset["Type"]): [
            rr["Value"] for rr in rrset["ResourceRecords"]]
        for rrset in _record_sets(route53, zone_id)
        if rrset["Type"] == "CNAME"
    }
    key = (record["Name"].rstrip("."), "CNAME")
    assert key in published, (
        f"the validation CNAME must be present in zone {zone_id}; the zone holds "
        f"{sorted(published)}"
    )
    assert [v.rstrip(".") for v in published[key]] == [record["Value"].rstrip(".")], (
        f"the published CNAME must target exactly what ACM asked for; zone holds "
        f"{published[key]!r}, ACM asked for {record['Value']!r}"
    )

    # --- the positive control: this account CAN drive a certificate to ISSUED. ---
    control_pem, control_key = _self_signed(f"control.{apex}")
    control_arn = _retry_throttle(lambda: acm.import_certificate(
        Certificate=control_pem, PrivateKey=control_key,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete_certificate(acm, control_arn))
    _poll_until(
        ctx, lambda: _retry_throttle(
            lambda: acm.describe_certificate(CertificateArn=control_arn))["Certificate"]["Status"],
        lambda status: status == "ISSUED",
        timeout_s=_budget_s(ctx, 120), interval_s=1,
        description="the import control reaching ISSUED (proving issuance works here at all)",
    )
    # --- the absence, held for a fixed window with the record live, as a freeze detector. ---
    window = _ABSENCE_WINDOW_S
    deadline = time.monotonic() + window
    reads = 0
    while time.monotonic() < deadline or reads < 5:
        detail_now = _retry_throttle(
            lambda: acm.describe_certificate(CertificateArn=cert_arn))["Certificate"]
        reads += 1
        assert detail_now["Status"] == "PENDING_VALIDATION", (
            f"ACM must NOT issue {apex!r} from a CNAME in an undelegated zone: after "
            f"{time.monotonic() - (deadline - window):.0f}s of a {window:.0f}s window "
            f"(after the import control reached ISSUED) the certificate "
            f"reports Status={detail_now['Status']!r} "
            f"(FailureReason {detail_now.get('FailureReason')!r})"
        )
        options_now = detail_now["DomainValidationOptions"]
        assert len(options_now) == 1, (
            f"the certificate covers one name, so it must carry one validation option; got "
            f"{len(options_now)}: {options_now!r}"
        )
        assert options_now[0]["ValidationStatus"] == "PENDING_VALIDATION", (
            f"the per-domain validation must remain pending; got "
            f"{options_now[0]['ValidationStatus']!r}"
        )
        # Freeze detector: the challenge must not be regenerated under a pending certificate,
        # or a client that published the old record would be chasing a moving target.
        assert options_now[0]["ResourceRecord"] == record, (
            f"ACM regenerated the validation record while the certificate was pending: it now "
            f"asks for {options_now[0]['ResourceRecord']!r}, it asked for {record!r}"
        )
        time.sleep(2)
    assert reads >= 5, (
        f"the absence window must contain at least 5 independent reads to be a freeze "
        f"detector; it contained {reads} over {window:.0f}s"
    )

    # --- second independent observable of the same absence, at the listing index. ---
    issued = _issued_arns(acm)
    assert control_arn in issued, (
        f"the import control must be indexed as ISSUED, or this leg cannot distinguish "
        f"'withheld' from 'the index is broken'; ListCertificates(ISSUED) returned "
        f"{len(issued)} ARNs without it"
    )
    assert cert_arn not in issued, (
        f"the DNS-validated certificate for {apex!r} must not appear in "
        f"ListCertificates(CertificateStatuses=['ISSUED']); it did"
    )

    # --- terminal read, through a different operation than every read above. ---
    statuses = _validation_statuses(acm, cert_arn)
    assert statuses == {apex: "PENDING_VALIDATION"}, (
        f"ListCertificateDomainValidations must still report {apex!r} as PENDING_VALIDATION and "
        f"nothing else; got {statuses!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
