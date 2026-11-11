"""custom-sql-dataset-column-schema-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-sql-dataset-column-schema-round-trip"
GROUP = "data-plane"
SERVICES = ["quicksight"]


def _mgmt_tags():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "s2r-schema"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The exact column schema (names, order, and data types) supplied on a CustomSql
    physical table round-trips faithfully through DescribeDataSet, not just the dataset
    name."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn = _ensure_quicksight_service_role(ctx)
    datasource_id = ctx.unique_name("s2r-schema-src-")
    dataset_id = ctx.unique_name("s2r-schema-ds-")

    src = qs.create_data_source(
        AwsAccountId=account_id,
        DataSourceId=datasource_id,
        Name=datasource_id,
        Type="ATHENA",
        DataSourceParameters={"AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}},
        Tags=_mgmt_tags(),
    )
    ctx.on_cleanup(
        lambda: qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    )
    _await_data_source_creation(qs, account_id, datasource_id)

    columns = [
        {"Name": "int_col", "Type": "INTEGER"},
        {"Name": "str_col", "Type": "STRING"},
        {"Name": "dec_col", "Type": "DECIMAL"},
    ]

    qs.create_data_set(
        AwsAccountId=account_id,
        DataSetId=dataset_id,
        Name=dataset_id,
        ImportMode="DIRECT_QUERY",
        PhysicalTableMap={
            "tbl1": {
                "CustomSql": {
                    "DataSourceArn": src["Arn"],
                    "Name": "q1",
                    "SqlQuery": "SELECT 1 AS int_col, 'x' AS str_col, CAST(1.5 AS DOUBLE) AS dec_col",
                    "Columns": columns,
                }
            }
        },
        Tags=_mgmt_tags(),
    )
    ctx.on_cleanup(lambda: qs.delete_data_set(AwsAccountId=account_id, DataSetId=dataset_id))

    described = qs.describe_data_set(AwsAccountId=account_id, DataSetId=dataset_id)["DataSet"]
    round_tripped = described["PhysicalTableMap"]["tbl1"]["CustomSql"]["Columns"]
    round_tripped_pairs = [(c["Name"], c["Type"]) for c in round_tripped]
    expected_pairs = [(c["Name"], c["Type"]) for c in columns]
    assert round_tripped_pairs == expected_pairs, round_tripped_pairs


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
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    return role_arn


def _await_data_source_creation(qs, account_id, datasource_id) -> None:
    """CreateDataSource returns before QuickSight has validated the Athena connection:
    the DataSource sits in CREATION_IN_PROGRESS and only reaches a terminal status
    (CREATION_SUCCESSFUL / CREATION_FAILED) asynchronously. Poll for that terminal
    status with a deadline instead of assuming the synchronous response means ready,
    and surface the target's own ErrorInfo on failure rather than a downstream
    CreateDataSet error that would only say the id was in a bad state."""
    import time

    deadline = time.monotonic() + 120.0
    status = None
    info = None
    while time.monotonic() < deadline:
        info = qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)[
            "DataSource"
        ]
        status = info.get("Status")
        if status == "CREATION_SUCCESSFUL":
            return
        if status == "CREATION_FAILED":
            raise AssertionError(f"quicksight data source creation failed: {info.get('ErrorInfo')}")
        time.sleep(5.0)
    raise AssertionError(f"quicksight data source never reached a terminal status: {status} ({info})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
