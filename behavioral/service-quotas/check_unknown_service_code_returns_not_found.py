"""unknown-service-code-returns-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "unknown-service-code-returns-not-found"
GROUP = "error-semantics"
SERVICES = ["service-quotas"]


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetServiceQuota and ListServiceQuotas both refuse a well-formed but unknown ServiceCode with
    NoSuchResourceException and their exact messages, and a vpc lookup still succeeds afterward."""
    sq = ctx.client("service-quotas")
    bogus_service = "sim2real-nonexistent-service-zzz"

    get_code, get_message = _error_code(lambda: sq.get_service_quota(ServiceCode=bogus_service, QuotaCode="L-00000000"))
    assert get_code == "NoSuchResourceException", (
        f"expected GetServiceQuota on unknown ServiceCode={bogus_service!r} to reject with "
        f"NoSuchResourceException, got {get_code!r}"
    )
    expected_get = "The request failed because the specified quota and service do not exist."
    assert get_message == expected_get, f"expected message {expected_get!r}, got {get_message!r}"

    list_code, list_message = _error_code(lambda: sq.list_service_quotas(ServiceCode=bogus_service))
    assert list_code == "NoSuchResourceException", (
        f"expected ListServiceQuotas on unknown ServiceCode={bogus_service!r} to reject with "
        f"NoSuchResourceException, got {list_code!r}"
    )
    expected_list = (
        "This service is not available in the current Region. "
        "Choose a different Region or a different service. "
    )
    assert list_message == expected_list, f"expected message {expected_list!r}, got {list_message!r}"

    listed = sq.list_service_quotas(ServiceCode="vpc")["Quotas"]
    assert listed, "expected at least one quota for ServiceCode=vpc"
    got = sq.get_service_quota(ServiceCode="vpc", QuotaCode=listed[0]["QuotaCode"])["Quota"]
    assert got["ServiceCode"] == "vpc", (
        f"expected the positive-control lookup to return ServiceCode='vpc', got {got['ServiceCode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
