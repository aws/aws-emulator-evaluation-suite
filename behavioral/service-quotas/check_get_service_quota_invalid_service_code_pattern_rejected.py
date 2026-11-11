"""get-service-quota-invalid-service-code-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-service-quota-invalid-service-code-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_REAL_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region
_BAD_SERVICE_CODE = "1bad!code"  # fails pattern: must start with a letter


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ServiceCode that fails the required naming pattern (must start with a
    letter, alnum/dash only) is rejected with IllegalArgumentException, while the
    identical call with a valid ServiceCode still succeeds (positive control)."""
    sq = ctx.client("service-quotas")

    code, message = _error_code(
        lambda: sq.get_service_quota(ServiceCode=_BAD_SERVICE_CODE, QuotaCode=_QUOTA_CODE)
    )
    assert code == "IllegalArgumentException", f"expected IllegalArgumentException, got {code!r}"
    expected = (
        "ServiceCode failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z][a-zA-Z0-9-]{1,63}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    try:
        control = sq.get_service_quota(ServiceCode=_REAL_SERVICE_CODE, QuotaCode=_QUOTA_CODE)[
            "Quota"
        ]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchResourceException":
            raise
        control = sq.get_aws_default_service_quota(
            ServiceCode=_REAL_SERVICE_CODE, QuotaCode=_QUOTA_CODE
        )["Quota"]
    assert control["ServiceCode"] == _REAL_SERVICE_CODE, (
        f"expected ServiceCode {_REAL_SERVICE_CODE!r}, got {control['ServiceCode']!r}"
    )
    assert control["QuotaCode"] == _QUOTA_CODE, (
        f"expected QuotaCode {_QUOTA_CODE!r}, got {control['QuotaCode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
