"""template-operations-require-organization-membership-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-operations-require-organization-membership-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region

# Service Quotas request templates are a single-home-region AWS Organizations feature:
# every template operation issued against any other Region is rejected with
# TemplatesNotAvailableInRegionException *before* organization membership is ever
# evaluated, on any account topology.
_TEMPLATE_REGION = "us-east-1"

# The exact refusal message, by topology. Only the member-account message is known; a
# standalone account is graded on the code alone.
_EXPECTED_MESSAGE = {
    "member": (
        "The request was called by a member account. To make this request, you must use the "
        "organization's master account."
    ),
}


def _error(fn):
    """Call fn(); return its botocore error (Code and Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _org_topology(ctx) -> str:
    """Return this account's real, self-reported Organizations topology: 'standalone' (no
    organization at all), 'member' (belongs to an organization but is not its management
    account), or 'management' (is the organization's own management account)."""
    org = ctx.client("organizations")
    try:
        info = org.describe_organization()["Organization"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "AWSOrganizationsNotInUseException":
            return "standalone"
        # Any other error (e.g. AccessDenied to the Organizations API itself)
        # means we cannot reliably determine topology.
        raise
    caller_account = ctx.client("sts").get_caller_identity()["Account"]
    return "management" if info["MasterAccountId"] == caller_account else "member"


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "identity:standalone", "phase:standalone", "plane:control")
def run(ctx) -> None:
    """Quota request template writes and reads in us-east-1 are refused for a caller that is not the
    organization's management account (NoAvailableOrganizationException standalone,
    AccessDeniedException with its exact message as a member), while unrelated calls still succeed."""
    try:
        topology = _org_topology(ctx)
    except ClientError:
        raise AssertionError(
            "could not determine AWS Organizations topology for this account "
            "(organizations:DescribeOrganization was denied) -- cannot safely "
            "assert the template-operations rejection boundary"
        )
    if topology == "management":
        raise AssertionError(
            "this account is its AWS Organization's management account; the rejection this "
            "check proves (NoAvailableOrganizationException for a standalone account, "
            "AccessDeniedException for a non-management member) does not reproduce from "
            "the management account itself"
        )
    expected_code = "NoAvailableOrganizationException" if topology == "standalone" else "AccessDeniedException"

    sq_templates = ctx.client("service-quotas", region=_TEMPLATE_REGION)

    error = _error(
        lambda: sq_templates.put_service_quota_increase_request_into_template(
            ServiceCode=_SERVICE_CODE,
            QuotaCode=_QUOTA_CODE,
            AwsRegion=ctx.region,
            DesiredValue=1000000,
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == expected_code, (
        f"expected PutServiceQuotaIncreaseRequestIntoTemplate to be rejected with "
        f"{expected_code} for a {topology} account, got {code!r}"
    )
    if topology in _EXPECTED_MESSAGE:
        assert message == _EXPECTED_MESSAGE[topology], (
            f"expected PutServiceQuotaIncreaseRequestIntoTemplate message "
            f"{_EXPECTED_MESSAGE[topology]!r}, got {message!r}"
        )

    # Effect absent: since template reads are gated the same way, nothing can have
    # been persisted -- the read path fails identically rather than returning an
    # entry that would prove a write actually landed.
    read_error = _error(
        lambda: sq_templates.get_service_quota_increase_request_from_template(
            ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE, AwsRegion=ctx.region
        )
    )
    read_code, read_message = read_error.get("Code"), read_error.get("Message")
    assert read_code == expected_code, (
        f"expected GetServiceQuotaIncreaseRequestFromTemplate to fail identically "
        f"(no template entry could have been persisted), got {read_code!r}"
    )
    if topology in _EXPECTED_MESSAGE:
        assert read_message == _EXPECTED_MESSAGE[topology], (
            f"expected GetServiceQuotaIncreaseRequestFromTemplate message "
            f"{_EXPECTED_MESSAGE[topology]!r}, got {read_message!r}"
        )

    # Positive control: unrelated, non-template Service Quotas calls still work.
    sq = ctx.client("service-quotas")
    control = sq.get_aws_default_service_quota(
        ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE
    )["Quota"]
    assert control["QuotaCode"] == _QUOTA_CODE, (
        f"positive control: expected GetAWSDefaultServiceQuota to keep working "
        f"(unrelated to the template gate), got quota code {control.get('QuotaCode')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
