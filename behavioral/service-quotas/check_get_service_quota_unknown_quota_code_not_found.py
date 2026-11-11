"""get-service-quota-unknown-quota-code-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-service-quota-unknown-quota-code-not-found"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_REAL_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region
_BOGUS_QUOTA_CODE = "L-00000000"  # syntactically valid, does not exist


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a QuotaCode real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects ServiceCode={_SERVICE_CODE}/QuotaCode={_BOGUS_QUOTA_CODE} with "
        f"NoSuchResourceException, but the call SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A well-formed but nonexistent QuotaCode is rejected with
    NoSuchResourceException, and a real quota remains normally retrievable before
    and after the failed lookup (positive control)."""
    sq = ctx.client("service-quotas")

    before = sq.get_aws_default_service_quota(
        ServiceCode=_SERVICE_CODE, QuotaCode=_REAL_QUOTA_CODE
    )["Quota"]

    code, message = _error_code(
        lambda: sq.get_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_BOGUS_QUOTA_CODE)
    )
    assert code == "NoSuchResourceException", (
        f"expected NoSuchResourceException for unknown QuotaCode={_BOGUS_QUOTA_CODE}, got {code!r}"
    )
    expected = "The request failed because the specified quota and service do not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = sq.get_aws_default_service_quota(
        ServiceCode=_SERVICE_CODE, QuotaCode=_REAL_QUOTA_CODE
    )["Quota"]
    assert after["QuotaCode"] == before["QuotaCode"] == _REAL_QUOTA_CODE, (
        f"real quota QuotaCode drifted across the failed lookup: before={before['QuotaCode']!r} "
        f"after={after['QuotaCode']!r} expected={_REAL_QUOTA_CODE!r}"
    )
    assert after["Value"] == before["Value"], (
        f"real quota Value changed across the failed lookup: before={before['Value']!r} "
        f"after={after['Value']!r} (a read must not mutate state)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
