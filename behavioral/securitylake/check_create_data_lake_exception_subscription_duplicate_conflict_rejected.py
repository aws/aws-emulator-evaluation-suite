"""create-data-lake-exception-subscription-duplicate-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-data-lake-exception-subscription-duplicate-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["securitylake"]
_ENTITLEMENT_MESSAGE = (
    "To perform this operation, your account must be a delegated Security Lake administrator account "
    "or a standalone Security Lake account."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:securitylake-data-lake")
def run(ctx) -> None:
    """Without a data lake entitlement, CreateDataLake, CreateDataLakeExceptionSubscription and
    GetDataLakeExceptionSubscription are refused with AccessDeniedException and the exact entitlement
    message, GetDataLakeSources with UnauthorizedException "Unauthorized", and no data lake is listed."""
    sl = ctx.client("securitylake")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # positive control: the control plane is reachable and the credentials are
    # valid -- ListDataLakes succeeds and reports no data lake, never an access error.
    before = sl.list_data_lakes(regions=[ctx.region])["dataLakes"]
    assert before == [], f"expected no data lake yet, got {before!r}"

    fake_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-slmsm-')}"
    code, message = _error_code_and_message(
        lambda: sl.create_data_lake(
            configurations=[{"region": ctx.region}], metaStoreManagerRoleArn=fake_role_arn
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}: {message}"
    assert message == _ENTITLEMENT_MESSAGE, f"expected the eligibility-gate message, got {message!r}"

    # effect absent, two independent reads: no data lake exists at either surface.
    # GetDataLakeSources on this account reports the SAME entitlement gate
    # (UnauthorizedException), not the ResourceNotFoundException an eligible account
    # with no data lake yet would get.
    after = sl.list_data_lakes(regions=[ctx.region])["dataLakes"]
    assert after == [], f"expected still no data lake, got {after!r}"
    sources_code, sources_message = _error_code_and_message(lambda: sl.get_data_lake_sources())
    assert sources_code == "UnauthorizedException", (
        f"expected GetDataLakeSources to report the same entitlement gate, got {sources_code!r}"
    )
    assert sources_message == "Unauthorized", f"expected the Unauthorized message, got {sources_message!r}"

    # Even the first exception subscription is unreachable without a data lake: a
    # mutating call gates on the same AccessDeniedException and message as CreateDataLake
    # (the GetDataLakeSources read above gates on UnauthorizedException instead).
    exc_code, exc_message = _error_code_and_message(
        lambda: sl.create_data_lake_exception_subscription(
            subscriptionProtocol="email",
            notificationEndpoint="sim2real-exc-first@example.com",
            exceptionTimeToLive=7,
        )
    )
    assert exc_code == "AccessDeniedException", (
        f"expected CreateDataLakeExceptionSubscription to also require the entitlement gate, "
        f"got {exc_code!r}: {exc_message}"
    )
    assert exc_message == _ENTITLEMENT_MESSAGE, f"expected the eligibility-gate message, got {exc_message!r}"

    # Terminal read, independent of the mutating call above: unlike GetDataLakeSources
    # (UnauthorizedException), this read gates the same way CreateDataLake and
    # CreateDataLakeExceptionSubscription do (AccessDeniedException).
    get_sub_code, get_sub_message = _error_code_and_message(
        lambda: sl.get_data_lake_exception_subscription()
    )
    assert get_sub_code == "AccessDeniedException", (
        f"expected GetDataLakeExceptionSubscription to report the same entitlement gate "
        f"(no subscription exists), got {get_sub_code!r}"
    )
    assert get_sub_message == _ENTITLEMENT_MESSAGE, f"expected the eligibility-gate message, got {get_sub_message!r}"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected ClientError, call unexpectedly succeeded")
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
