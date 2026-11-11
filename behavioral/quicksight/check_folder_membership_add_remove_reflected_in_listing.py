"""folder-membership-add-remove-reflected-in-listing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "folder-membership-add-remove-reflected-in-listing"
GROUP = "state"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding a data source to a folder makes it show up in ListFolderMembers, and
    removing it makes it disappear again."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn = _ensure_quicksight_service_role(ctx)
    folder_id = ctx.unique_name("s2r-folder-")
    datasource_id = ctx.unique_name("s2r-fmember-src-")

    qs.create_folder(
        AwsAccountId=account_id,
        FolderId=folder_id,
        Name=folder_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: qs.delete_folder(AwsAccountId=account_id, FolderId=folder_id))

    _create_data_source_with_retry(qs, account_id, datasource_id, role_arn, CHECK)
    ctx.on_cleanup(
        lambda: qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    )

    qs.create_folder_membership(
        AwsAccountId=account_id,
        FolderId=folder_id,
        MemberId=datasource_id,
        MemberType="DATASOURCE",
    )
    members = qs.list_folder_members(AwsAccountId=account_id, FolderId=folder_id)[
        "FolderMemberList"
    ]
    assert any(m["MemberId"] == datasource_id for m in members), members

    qs.delete_folder_membership(
        AwsAccountId=account_id,
        FolderId=folder_id,
        MemberId=datasource_id,
        MemberType="DATASOURCE",
    )
    members_after = qs.list_folder_members(AwsAccountId=account_id, FolderId=folder_id)[
        "FolderMemberList"
    ]
    assert not any(m["MemberId"] == datasource_id for m in members_after), members_after


def _ensure_quicksight_subscribed(qs, account_id) -> None:
    """QuickSight requires a one-time account subscription before any resource
    operation succeeds. Idempotently create it (ENTERPRISE / IAM_ONLY) and wait
    for ACCOUNT_CREATED if the account hasn't been subscribed yet."""
    import time

    from botocore.exceptions import ClientError

    try:
        info = qs.describe_account_subscription(AwsAccountId=account_id)["AccountInfo"]
        if info.get("AccountSubscriptionStatus") in ("ACCOUNT_CREATED", "ENABLED"):
            return
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    try:
        qs.create_account_subscription(
            AwsAccountId=account_id,
            AccountName=f"sim2real-behav-qs-{account_id}",
            NotificationEmail="sim2real-probe@example.com",
            AuthenticationMethod="IAM_ONLY",
            Edition="ENTERPRISE",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceExistsException",):
            raise

    deadline = time.monotonic() + 300.0
    last = None
    while time.monotonic() < deadline:
        info = qs.describe_account_subscription(AwsAccountId=account_id)["AccountInfo"]
        last = info.get("AccountSubscriptionStatus")
        if last in ("ACCOUNT_CREATED", "ENABLED"):
            return
        if last == "ACCOUNT_CREATION_FAILED":
            raise AssertionError(f"quicksight account subscription failed: {info}")
        time.sleep(2)
    raise AssertionError(f"quicksight account subscription never became ready: {last}")


def _create_data_source_with_retry(qs, account_id, datasource_id, role_arn, check_id) -> None:
    """The IAM role handed to AthenaParameters.RoleArn may not have propagated through
    IAM yet when it was just created, so QuickSight can transiently refuse to assume
    it. Retry on that specific error with a bounded deadline; any other error (or a
    deadline miss) is a real failure, never swallowed."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            qs.create_data_source(
                AwsAccountId=account_id,
                DataSourceId=datasource_id,
                Name=datasource_id,
                Type="ATHENA",
                DataSourceParameters={
                    "AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}
                },
                Tags=[{"Key": "sim2real", "Value": check_id}],
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = e
            time.sleep(5.0)
    raise AssertionError(
        f"create_data_source never succeeded after IAM role propagation retries: {last}"
    )


def _ensure_quicksight_service_role(ctx) -> str:
    """CreateDataSource for Athena/S3-backed types needs QuickSight's IAM execution
    role (normally provisioned once via the console's "Security & permissions" flow,
    which the API can't do). Recreate an equivalent role idempotently via IAM and pass
    its ARN through AthenaParameters.RoleArn to override the (missing) account-wide
    default so the account can provision ATHENA data sources through the API
    alone. Returns the role's ARN."""
    iam = ctx.client("iam")
    role_name = "aws-quicksight-service-role-v0"
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"quicksight.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust,
            Description="sim2real quicksight behavioral checks: default QuickSight execution role",
        )["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSQuicksightAthenaAccess",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ):
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except Exception:
            pass

    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
