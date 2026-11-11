"""get-data-lake-sources-without-data-lake-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-data-lake-sources-without-data-lake-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["securitylake"]
_ENTITLEMENT_MESSAGE = (
    "To perform this operation, your account must be a delegated Security Lake administrator account "
    "or a standalone Security Lake account."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:securitylake-data-lake")
def run(ctx) -> None:
    """Without the delegated-administrator or standalone status, GetDataLakeSources is refused with
    UnauthorizedException "Unauthorized", not ResourceNotFoundException; CreateDataLake is refused with
    AccessDeniedException and the entitlement message, and ListDataLakes stays empty."""
    sl = ctx.client("securitylake")

    lakes = sl.list_data_lakes(regions=[ctx.region])["dataLakes"]
    assert lakes == [], f"expected no data lake yet, got {lakes!r}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    for kwargs in ({}, {"accounts": [account_id]}):
        code, message = _error_code(lambda kwargs=kwargs: sl.get_data_lake_sources(**kwargs))
        assert code == "UnauthorizedException", f"GetDataLakeSources({kwargs!r}): expected UnauthorizedException, got {code!r}"
        assert message == "Unauthorized", f"GetDataLakeSources({kwargs!r}): expected message 'Unauthorized', got {message!r}"

    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-slmsm-')}"
    code, message = _error_code(
        lambda: sl.create_data_lake(configurations=[{"region": ctx.region}], metaStoreManagerRoleArn=role_arn)
    )
    assert code == "AccessDeniedException", f"CreateDataLake: expected AccessDeniedException, got {code!r}"
    assert message == _ENTITLEMENT_MESSAGE, f"CreateDataLake: expected the entitlement message, got {message!r}"

    lakes = sl.list_data_lakes(regions=[ctx.region])["dataLakes"]
    assert lakes == [], f"rejected CreateDataLake should have had no effect, got {lakes!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected a ClientError, call succeeded")
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
