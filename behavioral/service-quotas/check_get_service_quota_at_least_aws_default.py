"""get-service-quota-at-least-aws-default."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-service-quota-at-least-aws-default"
GROUP = "state"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The applied account quota never falls below the AWS default baseline value."""
    sq = ctx.client("service-quotas")

    default_quota = sq.get_aws_default_service_quota(
        ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE
    )["Quota"]

    try:
        applied_quota = sq.get_service_quota(
            ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE
        )["Quota"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchResourceException":
            raise AssertionError(
                "no applied (account-level) quota value is available for "
                f"{_SERVICE_CODE}/{_QUOTA_CODE} in this account/region -- only the "
                "AWS default is retrievable, so the applied-vs-default invariant "
                "cannot be exercised"
            )
        raise

    assert applied_quota["ServiceCode"] == _SERVICE_CODE, (
        f"expected ServiceCode {_SERVICE_CODE!r}, got {applied_quota['ServiceCode']!r}"
    )
    assert applied_quota["QuotaCode"] == _QUOTA_CODE, (
        f"expected QuotaCode {_QUOTA_CODE!r}, got {applied_quota['QuotaCode']!r}"
    )
    assert applied_quota["Value"] >= default_quota["Value"], (
        f"applied quota value {applied_quota['Value']} is below the AWS default "
        f"baseline {default_quota['Value']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
