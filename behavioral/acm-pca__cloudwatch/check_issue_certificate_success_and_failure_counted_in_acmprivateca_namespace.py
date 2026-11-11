"""issue-certificate-success-and-failure-counted-in-acmprivateca-namespace."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "issue-certificate-success-and-failure-counted-in-acmprivateca-namespace"
GROUP = "metrics-delivery"
SERVICES = ["acm-pca", "cloudwatch"]

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_NAMESPACE = "AWS/ACMPrivateCA"

# The CA lives 2 days so a 7-day leaf is refused for exceeding its notAfter. Both leaf values are
# inside the SHORT_LIVED_CERTIFICATE 7-day ceiling, so the usage mode cannot be the cause.
_CA_DAYS = 2
_GOOD_LEAF_DAYS = 1
_BAD_LEAF_DAYS = 7
# Exact expected count for this CA. Failure has no constant: a synchronous refusal emits no
# Failure series at all, so that assertion is against None.
_EXPECTED_SUCCESS = 2
_ACTIVATE_TIMEOUT_S = 180.0
_LEAF_TIMEOUT_S = 90.0
_METRIC_POLL_TIMEOUT_S = 600.0
_METRIC_POLL_INTERVAL_S = 2.0
# Failure is read this many times, this far apart, once the post-refusal Success has landed.
_ABSENCE_SAMPLES = 3
_ABSENCE_INTERVAL_S = 2.0
_TEARDOWN_TIMEOUT_S = 420.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return it. Raises on timeout."""
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


def _require_local_crypto() -> None:
    """Fail before any create if the cryptography package is missing."""
    from cryptography import x509  # noqa: F401


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Disable then delete the CA, polling until Status == "DELETED"; raise if it never gets there.

    DeleteCertificateAuthority refuses an ACTIVE CA, so it is DISABLED first.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError:
            return  # not addressable any more; nothing left to bill
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError:
                pass  # teardown-only: re-read the status and retry on the next pass
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn,
                PermanentDeletionTimeInDays=_MIN_DELETION_DAYS,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: certificate authority {ca_arn} never reached "
        f"Status=DELETED within {_TEARDOWN_TIMEOUT_S}s (last observed {last_status!r}). It is "
        f"STILL BILLING. Delete it manually: UpdateCertificateAuthority(Status='DISABLED') "
        f"then DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, scenario, **overrides):
    """Create a ROOT CA and register its teardown immediately.

    Tagged because a CA has no caller-chosen name, only a server-minted id.
    """
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")[:64]},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": _USAGE_MODE,
        "Tags": [{"Key": "sim2real", "Value": scenario}],
    }
    body.update(overrides)
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            throttles = ("ThrottlingException", "Throttling", "RequestLimitExceeded")
            if code in throttles and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _fetch_csr(ctx, ca_arn, *, timeout_s):
    """GetCertificateAuthorityCsr, polling through the creation-in-progress guard."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                return None
            raise

    return _poll_until(
        ctx, _probe, lambda v: bool(v), timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )


def _await_certificate(ctx, ca_arn, cert_arn, *, timeout_s):
    """GetCertificate, polling through RequestInProgressException until signing completes.

    Returns (certificate_pem, chain_pem_or_None).
    """
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RequestInProgressException":
                return None
            raise

    got = _poll_until(
        ctx, _probe, lambda v: bool(v and v.get("Certificate")),
        timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description=f"GetCertificate returning a signed certificate for {cert_arn}",
    )
    return got["Certificate"], got.get("CertificateChain")


def _activate_root_ca_short(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR.

    The documented root-CA installation sequence (privateca userguide, "Install a root CA
    certificate"). Returns the CA certificate PEM.
    """
    pca = ctx.client("acm-pca")
    _poll_until(
        ctx, lambda: _describe(ctx, ca_arn), lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )
    csr_pem = _fetch_csr(ctx, ca_arn, timeout_s=timeout_s)
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": _CA_DAYS, "Type": "DAYS"},
    )["CertificateArn"]
    ca_cert_pem, _ = _await_certificate(ctx, ca_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("ascii")
    )
    _poll_until(
        ctx, lambda: _describe(ctx, ca_arn), lambda c: c.get("Status") == "ACTIVE",
        timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return ca_cert_pem


def _new_csr(common_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _issue(ctx, ca_arn, csr_pem, days):
    return ctx.client("acm-pca").issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity={"Value": days, "Type": "DAYS"},
    )["CertificateArn"]


def _ca_scoped_dimensions(ctx, metric_name, ca_id):
    """Dimension sets ListMetrics reports for `metric_name` that mention this run's CA id.

    Each returned dimension list is usable directly as a GetMetricStatistics Dimensions argument.
    """
    cw = ctx.client("cloudwatch")
    found = []
    paginator = cw.get_paginator("list_metrics")
    for page in paginator.paginate(Namespace=_NAMESPACE, MetricName=metric_name):
        for metric in page.get("Metrics", []):
            dims = metric.get("Dimensions", [])
            if any(ca_id in str(d.get("Value", "")) for d in dims):
                found.append(dims)
    return found


def _metric_sum(ctx, metric_name, dimensions, start, end):
    """The Sum of `metric_name` over [start, end] for exactly `dimensions`, or None if no data.

    None means the series does not exist; 0.0 means it exists and counted nothing.
    """
    got = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=["Sum"],
    )
    points = got.get("Datapoints", [])
    if not points:
        return None
    return sum(p["Sum"] for p in points)


def _metric_average(ctx, metric_name, dimensions, start, end):
    """The mean of `metric_name`'s Average datapoints over the window, or None if no data."""
    got = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=["Average"],
    )
    points = got.get("Datapoints", [])
    if not points:
        return None
    return sum(p["Average"] for p in points) / len(points)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/privateca/latest/userguide/PcaCloudWatch.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:metrics", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """Two successful IssueCertificate calls count exactly 2 in AWS/ACMPrivateCA Success; a refusal
    for exceeding the CA's NotAfter leaves no Failure series; Time is positive and bounded.

    Reference: https://docs.aws.amazon.com/privateca/latest/userguide/PcaCloudWatch.html
    """
    _require_local_crypto()

    scenario = "acm-pca-cloudwatch-issue-metrics"

    ca_arn = _create_ca(ctx, scenario)
    _activate_root_ca_short(ctx, ca_arn, timeout_s=_ACTIVATE_TIMEOUT_S)
    ca_id = ca_arn.rsplit("/", 1)[-1]

    status = _describe(ctx, ca_arn)["Status"]
    assert status == "ACTIVE", (
        f"the CA must be ACTIVE before any issuance is attempted, or an InvalidStateException "
        f"would be counted instead of the refusal this check is about; Describe reports "
        f"{status!r}"
    )

    csr_pem = _new_csr("metrics.sim2real.invalid")

    # The metric window opens BEFORE the first issuance and is measured on the live clock, so
    # no pre-existing datapoint can fall inside it.
    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    t0 = time.monotonic()

    # ---- one issuance that must SUCCEED, then one that must be REFUSED for exceeding the CA's
    # own notAfter, then a second that must SUCCEED: the refusal is ordered before the last
    # success, so a Failure datapoint would be delivered no later than that success ----
    cert_arn = _issue(ctx, ca_arn, csr_pem, _GOOD_LEAF_DAYS)
    _await_certificate(ctx, ca_arn, cert_arn, timeout_s=_LEAF_TIMEOUT_S)

    refused = _error(lambda: _issue(ctx, ca_arn, csr_pem, _BAD_LEAF_DAYS))
    assert refused == (
        "ValidationException",
        "The certificate validity specified exceeds the certificate authority validity.",
    ), (
        f"a leaf whose {_BAD_LEAF_DAYS}-day validity outlives the CA's own {_CA_DAYS}-day "
        f"certificate must be refused with ValidationException before its metric can mean "
        f"anything -- and the {_GOOD_LEAF_DAYS}-day issuance above SUCCEEDED on this same "
        f"CA, so this is the validity boundary and not a broken CA; got {refused!r}"
    )

    cert_arn = _issue(ctx, ca_arn, csr_pem, _GOOD_LEAF_DAYS)
    _await_certificate(ctx, ca_arn, cert_arn, timeout_s=_LEAF_TIMEOUT_S)
    elapsed_ms = (time.monotonic() - t0) * 1000.0

    # ---- discover the dimension rather than guessing it ----
    dim_sets = _poll_until(
        ctx, lambda: _ca_scoped_dimensions(ctx, "Success", ca_id),
        lambda v: bool(v),
        timeout_s=_budget_s(ctx, _METRIC_POLL_TIMEOUT_S), interval_s=_METRIC_POLL_INTERVAL_S,
        description=(
            f"ListMetrics reporting a {_NAMESPACE} Success series dimensioned on this run's "
            f"CA {ca_id}"
        ),
    )
    dims = dim_sets[0]
    assert any(ca_id in str(d.get("Value", "")) for d in dims), (
        f"the discovered dimension set must identify THIS CA for the counts below to be exact "
        f"rather than account-wide: expected a dimension value containing {ca_id!r}, got "
        f"{dims!r}"
    )

    def _window_end():
        return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)

    # ---- Success: exactly the two that succeeded ----
    success = _poll_until(
        ctx, lambda: _metric_sum(ctx, "Success", dims, window_start, _window_end()),
        lambda v: v is not None and v >= _EXPECTED_SUCCESS,
        timeout_s=_budget_s(ctx, _METRIC_POLL_TIMEOUT_S), interval_s=_METRIC_POLL_INTERVAL_S,
        description=(
            f"{_NAMESPACE} Success reaching {_EXPECTED_SUCCESS} for CA {ca_id} -- the metric "
            f"is documented as applying only to IssueCertificate"
        ),
    )
    assert success == _EXPECTED_SUCCESS, (
        f"{_EXPECTED_SUCCESS} IssueCertificate calls succeeded against CA {ca_id} and one was "
        f"refused, so the {_NAMESPACE} Success sum over this run's own window must be exactly "
        f"{_EXPECTED_SUCCESS}; CloudWatch reports {success!r}. A target counting every API "
        f"call regardless of outcome would report {_EXPECTED_SUCCESS + 1}"
    )

    # ---- Failure: absent for a synchronous validation refusal ----
    # The Success sum above includes the issuance made after the refusal, so a Failure datapoint
    # for the refusal is already delivered; it is read on several independent samples.
    failure_dims_found: list = []
    failure_sum: float | None = None
    for sample in range(_ABSENCE_SAMPLES):
        if sample:
            time.sleep(_ABSENCE_INTERVAL_S)
        failure_dims_found = _ca_scoped_dimensions(ctx, "Failure", ca_id)
        failure_sum = _metric_sum(ctx, "Failure", dims, window_start, _window_end())
        if failure_dims_found or failure_sum is not None:
            break
    assert not failure_dims_found, (
        f"a {_BAD_LEAF_DAYS}-day-validity refusal against CA {ca_id} was measured to leave NO "
        f"{_NAMESPACE} Failure series naming this CA at all, read after the Success metric for "
        f"an issuance made AFTER the refusal was delivered -- but ListMetrics reports a "
        f"dimension set naming this CA under MetricName=Failure: {failure_dims_found!r}. Either "
        f"real AWS's behaviour changed since this check was measured, or this target fabricates "
        f"a Failure series real AWS does not emit for a synchronous refusal"
    )
    assert failure_sum is None, (
        f"the {_NAMESPACE} Failure sum for CA {ca_id}, read with the SAME dimension set Success "
        f"was discovered under, must stay absent (None, not merely 0.0 -- a series that exists "
        f"and counted nothing is a different, weaker claim) for the refused issuance above; "
        f"CloudWatch reports {failure_sum!r}"
    )

    # ---- Time: a positive latency, bounded above by what this run actually measured ----
    avg_ms = _poll_until(
        ctx, lambda: _metric_average(ctx, "Time", dims, window_start, _window_end()),
        lambda v: v is not None,
        timeout_s=_budget_s(ctx, _METRIC_POLL_TIMEOUT_S), interval_s=_METRIC_POLL_INTERVAL_S,
        description=f"{_NAMESPACE} Time reporting an issuance latency for CA {ca_id}",
    )
    assert avg_ms > 0.0, (
        f"Time is documented as 'the time in milliseconds between an issuance request and the "
        f"completion (or failure) of issuance', so it cannot be {avg_ms!r} for three real "
        f"issuance attempts"
    )
    assert avg_ms <= elapsed_ms, (
        f"the reported per-issuance latency {avg_ms:.0f}ms exceeds the {elapsed_ms:.0f}ms this "
        f"run spent on ALL THREE issuances combined, measured on the local monotonic clock, so "
        f"it cannot be a latency this service observed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
