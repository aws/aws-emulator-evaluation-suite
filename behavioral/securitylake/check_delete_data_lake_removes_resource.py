"""delete-data-lake-removes-resource."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-data-lake-removes-resource"
GROUP = "state-lifecycle"
SERVICES = ["securitylake"]

_MSM_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonSecurityLakeMetastoreManager"
_ENTITLEMENT_MESSAGE = (
    "To perform this operation, your account must be a delegated Security Lake administrator account "
    "or a standalone Security Lake account."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:securitylake-data-lake")
def run(ctx) -> None:
    """For an organization member that is neither a delegated Security Lake administrator nor a
    standalone account, CreateDataLake is refused with AccessDeniedException and the entitlement
    message, leaving no data lake; DeleteDataLake and GetDataLakeSources answer UnauthorizedException."""
    sl = ctx.client("securitylake")

    lakes = sl.list_data_lakes(regions=[ctx.region])["dataLakes"]
    assert lakes == [], f"expected no data lake in {ctx.region}, got {lakes!r}"

    role_arn = _create_metastore_role(ctx)
    create_code, create_message = _error_detail(
        lambda: sl.create_data_lake(configurations=[{"region": ctx.region}], metaStoreManagerRoleArn=role_arn)
    )
    assert create_code == "AccessDeniedException", (
        f"expected CreateDataLake to be denied with AccessDeniedException, got {create_code!r}: {create_message!r}"
    )
    assert create_message == _ENTITLEMENT_MESSAGE, (
        f"expected the admin/standalone-account message, got {create_message!r}"
    )

    lakes_after_denied_create = sl.list_data_lakes(regions=[ctx.region])["dataLakes"]
    assert lakes_after_denied_create == [], (
        f"a denied CreateDataLake must not leave a partial resource, got {lakes_after_denied_create!r}"
    )

    delete_code, delete_message = _error_detail(lambda: sl.delete_data_lake(regions=[ctx.region]))
    assert delete_code == "UnauthorizedException", (
        f"expected DeleteDataLake to reject with UnauthorizedException, got {delete_code!r}: {delete_message!r}"
    )
    assert delete_message == "Unauthorized", f"expected DeleteDataLake's Unauthorized message, got {delete_message!r}"

    sources_code, sources_message = _error_detail(lambda: sl.get_data_lake_sources(accounts=[]))
    assert sources_code == "UnauthorizedException", (
        f"expected GetDataLakeSources to reject with UnauthorizedException, got "
        f"{sources_code!r}: {sources_message!r}"
    )
    assert sources_message == "Unauthorized", (
        f"expected GetDataLakeSources' Unauthorized message, got {sources_message!r}"
    )


def _error_detail(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _create_metastore_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-slmsm-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_MSM_POLICY_ARN)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_MSM_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
