"""idc-and-integration-ops-semantics."""

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

CHECK = "idc-and-integration-ops-semantics"
GROUP = 'error-semantics'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IdC applications and zero-ETL integrations report their own not-exists/not-found codes."""
    rs = ctx.client("redshift")
    account = ctx.client("sts").get_caller_identity()["Account"]
    idc_arn = f"arn:aws:redshift:{ctx.region}:{account}:redshiftidcapplication:11111111-1111-1111-1111-111111111111"
    integration_arn = f"arn:aws:redshift:{ctx.region}:{account}:integration:11111111-1111-1111-1111-111111111111"
    cases = {
        "DescribeRedshiftIdcApplications": lambda: rs.describe_redshift_idc_applications(
            RedshiftIdcApplicationArn=idc_arn
        ),
        "DeleteRedshiftIdcApplication": lambda: rs.delete_redshift_idc_application(
            RedshiftIdcApplicationArn=idc_arn
        ),
        "ModifyRedshiftIdcApplication": lambda: rs.modify_redshift_idc_application(
            RedshiftIdcApplicationArn=idc_arn
        ),
        "DescribeIntegrations": lambda: rs.describe_integrations(IntegrationArn=integration_arn),
        "DeleteIntegration": lambda: rs.delete_integration(IntegrationArn=integration_arn),
        "ModifyIntegration": lambda: rs.modify_integration(
            IntegrationArn=integration_arn, Description="behavioral fidelity check"
        ),
        "DescribeInboundIntegrations": lambda: rs.describe_inbound_integrations(
            IntegrationArn=integration_arn
        ),
    }
    observed = _probe_codes(cases)
    expected = {
        "DescribeRedshiftIdcApplications": "RedshiftIdcApplicationNotExists",
        "DeleteRedshiftIdcApplication": "RedshiftIdcApplicationNotExists",
        "ModifyRedshiftIdcApplication": "RedshiftIdcApplicationNotExists",
        "DescribeIntegrations": "IntegrationNotFoundFault",
        "DeleteIntegration": "IntegrationNotFoundFault",
        "ModifyIntegration": "IntegrationNotFoundFault",
        "DescribeInboundIntegrations": "IntegrationNotFoundFault",
    }
    assert observed == expected, f"idc/integration contract drift:\n expected={expected}\n observed={observed}"

    # Effect-absence, via an independent unfiltered list read: none of the rejected
    # Modify/Delete calls above may have silently taken effect despite reporting a
    # not-exists/not-found error.
    listed_idc = {
        app["RedshiftIdcApplicationArn"]
        for app in rs.describe_redshift_idc_applications().get("RedshiftIdcApplications", [])
    }
    assert idc_arn not in listed_idc, (
        f"a rejected IdC application call must not have registered the arn: {idc_arn} in {listed_idc}"
    )
    listed_integrations = {
        integ["IntegrationArn"] for integ in rs.describe_integrations().get("Integrations", [])
    }
    assert integration_arn not in listed_integrations, (
        f"a rejected integration call must not have registered the arn: {integration_arn} in {listed_integrations}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
