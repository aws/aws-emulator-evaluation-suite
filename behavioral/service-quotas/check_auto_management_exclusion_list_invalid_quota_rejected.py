"""auto-management-exclusion-list-invalid-quota-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "auto-management-exclusion-list-invalid-quota-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:service-quotas-auto-management")
def run(ctx) -> None:
    """StartAutoManagement with an ExclusionList quota code that does not exist under a real service is
    refused with IllegalArgumentException and its exact message and leaves the Automatic Management
    configuration unchanged; the same call naming a real quota code reaches ENABLED."""
    sq = ctx.client("service-quotas")

    def snapshot():
        try:
            cfg = sq.get_auto_management_configuration()
            return (cfg.get("OptInStatus"), cfg.get("OptInType"))
        except Exception as err:  # NoSuchResourceException: never started
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                return (None, None)
            raise

    before = snapshot()

    bogus_service, bogus_quota = "vpc", "L-00000000"
    code, message = _client_error(
        lambda: sq.start_auto_management(
            OptInLevel="ACCOUNT",
            OptInType="NotifyOnly",
            ExclusionList={bogus_service: [bogus_quota]},
        )
    )
    assert code == "IllegalArgumentException", code
    expected = f"Service code '{bogus_service}' with limit code '{bogus_quota}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = snapshot()
    assert after == before, f"auto-management config changed despite rejected call: {before!r} -> {after!r}"

    lambda_quotas = sq.list_service_quotas(ServiceCode="lambda")["Quotas"]
    adjustable = next((q for q in lambda_quotas if q["Adjustable"]), None)
    assert adjustable is not None, "expected at least one adjustable lambda quota"

    sq.start_auto_management(
        OptInLevel="ACCOUNT",
        OptInType="NotifyOnly",
        ExclusionList={"lambda": [adjustable["QuotaCode"]]},
    )
    ctx.on_cleanup(lambda: _swallow(lambda: sq.stop_auto_management()))
    enabled = sq.get_auto_management_configuration()
    assert enabled["OptInStatus"] == "ENABLED", f"expected ENABLED after valid call, got {enabled['OptInStatus']!r}"


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResourceException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
