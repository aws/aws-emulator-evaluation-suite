"""malformed-service-code-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "malformed-service-code-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetServiceQuota with a ServiceCode that fails ^[a-zA-Z][a-zA-Z0-9-]{1,63}$ is refused server-side
    with IllegalArgumentException and its exact message, and a well-formed vpc lookup still succeeds."""
    sq = ctx.client("service-quotas")

    code, message = _error_code(
        lambda: sq.get_service_quota(ServiceCode="not a valid code!", QuotaCode="L-00000000")
    )
    assert code == "IllegalArgumentException", f"expected IllegalArgumentException, got {code!r}"
    expected = (
        "ServiceCode failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z][a-zA-Z0-9-]{1,63}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = sq.list_service_quotas(ServiceCode="vpc")["Quotas"]
    assert listed, "expected at least one quota for ServiceCode=vpc"
    quota_code = listed[0]["QuotaCode"]
    got = sq.get_service_quota(ServiceCode="vpc", QuotaCode=quota_code)["Quota"]
    assert got["ServiceCode"] == "vpc", f"expected ServiceCode=vpc, got {got['ServiceCode']!r}"
    assert got["QuotaCode"] == quota_code, (
        f"expected QuotaCode={quota_code!r}, got {got['QuotaCode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
