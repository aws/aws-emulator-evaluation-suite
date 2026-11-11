"""custom-domain-and-partner-ops-semantics."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}

CHECK = "custom-domain-and-partner-ops-semantics"
GROUP = 'error-semantics'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Custom-domain and partner-integration operations resolve their parent cluster first."""
    rs = ctx.client("redshift")
    account = ctx.client("sts").get_caller_identity()["Account"]
    missing_cluster = ctx.unique_name("sim2real-behav-rs-cdcl-")
    domain = "sim2real-behav.example.com"
    cert_arn = f"arn:aws:acm:{ctx.region}:{account}:certificate/11111111-1111-1111-1111-111111111111"
    cases = {
        "DescribeCustomDomainAssociations": lambda: rs.describe_custom_domain_associations(
            CustomDomainName=domain
        ),
        "CreateCustomDomainAssociation": lambda: rs.create_custom_domain_association(
            ClusterIdentifier=missing_cluster, CustomDomainName=domain, CustomDomainCertificateArn=cert_arn
        ),
        "ModifyCustomDomainAssociation": lambda: rs.modify_custom_domain_association(
            ClusterIdentifier=missing_cluster, CustomDomainName=domain, CustomDomainCertificateArn=cert_arn
        ),
        "DeleteCustomDomainAssociation": lambda: rs.delete_custom_domain_association(
            ClusterIdentifier=missing_cluster, CustomDomainName=domain
        ),
        "DescribePartners": lambda: rs.describe_partners(
            AccountId=account, ClusterIdentifier=missing_cluster
        ),
        "AddPartner": lambda: rs.add_partner(
            AccountId=account, ClusterIdentifier=missing_cluster, DatabaseName="devdb", PartnerName="Datacoral"
        ),
        "DeletePartner": lambda: rs.delete_partner(
            AccountId=account, ClusterIdentifier=missing_cluster, DatabaseName="devdb", PartnerName="Datacoral"
        ),
        "UpdatePartnerStatus": lambda: rs.update_partner_status(
            AccountId=account,
            ClusterIdentifier=missing_cluster,
            DatabaseName="devdb",
            PartnerName="Datacoral",
            Status="Active",
        ),
    }
    observed = _probe_codes(cases)
    expected = dict.fromkeys(cases, "ClusterNotFound")
    expected["DescribeCustomDomainAssociations"] = "CustomDomainAssociationNotFoundFault"
    assert observed == expected, f"custom-domain/partner contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
