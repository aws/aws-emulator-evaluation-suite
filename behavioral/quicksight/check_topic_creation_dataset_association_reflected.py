"""topic-creation-dataset-association-reflected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "topic-creation-dataset-association-reflected"
GROUP = "state"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Topic created with a DataSets association exposes that exact dataset ARN back
    out through DescribeTopic."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn, role_just_created = _ensure_quicksight_service_role(ctx)
    datasource_id = ctx.unique_name("s2r-topic-src-")
    dataset_id = ctx.unique_name("s2r-topic-ds-")
    topic_id = ctx.unique_name("s2r-topic-")

    ctx.on_cleanup(
        lambda: qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    )
    src = _create_data_source_awaiting_role_propagation(
        qs, account_id, datasource_id, role_arn, CHECK, retry_on_failure=role_just_created
    )

    dataset = qs.create_data_set(
        AwsAccountId=account_id,
        DataSetId=dataset_id,
        Name=dataset_id,
        ImportMode="DIRECT_QUERY",
        PhysicalTableMap={
            "tbl1": {
                "CustomSql": {
                    "DataSourceArn": src["Arn"],
                    "Name": "q1",
                    "SqlQuery": "SELECT 1 AS col",
                    "Columns": [{"Name": "col", "Type": "INTEGER"}],
                }
            }
        },
        LogicalTableMap={
            "logical1": {
                "Alias": "logical1",
                "Source": {"PhysicalTableId": "tbl1"},
            }
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: qs.delete_data_set(AwsAccountId=account_id, DataSetId=dataset_id))
    dataset_arn = dataset["Arn"]

    qs.create_topic(
        AwsAccountId=account_id,
        TopicId=topic_id,
        Topic={
            "Name": topic_id,
            "DataSets": [
                {
                    "DatasetArn": dataset_arn,
                    "DatasetName": dataset_id,
                    "Columns": [{"ColumnName": "col"}],
                }
            ],
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: qs.delete_topic(AwsAccountId=account_id, TopicId=topic_id))

    described = qs.describe_topic(AwsAccountId=account_id, TopicId=topic_id)["Topic"]
    by_arn = {d["DatasetArn"]: d for d in described["DataSets"]}
    assert dataset_arn in by_arn, (dataset_arn, list(by_arn))
    reflected = by_arn[dataset_arn]
    assert reflected["DatasetName"] == dataset_id, reflected
    reflected_columns = {c["ColumnName"] for c in reflected.get("Columns", [])}
    assert "col" in reflected_columns, reflected_columns


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


def _ensure_quicksight_service_role(ctx) -> tuple[str, bool]:
    """CreateDataSource for Athena/S3-backed types needs QuickSight's IAM execution
    role (normally provisioned once via the console's "Security & permissions" flow,
    which the API can't do). Recreate an equivalent role idempotently via IAM and pass
    its ARN through AthenaParameters.RoleArn to override the (missing) account-wide
    default so the account can provision ATHENA data sources through the API
    alone. Returns (the role's ARN, whether this call created it just now)."""
    iam = ctx.client("iam")
    role_name = "aws-quicksight-service-role-v0"
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"quicksight.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    created_now = False
    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust,
            Description="sim2real quicksight behavioral checks: default QuickSight execution role",
        )["Role"]["Arn"]
        created_now = True
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

    return role_arn, created_now


def _create_data_source_awaiting_role_propagation(
    qs, account_id, datasource_id, role_arn, check_name, *, retry_on_failure, timeout_s=120.0, interval_s=10.0
):
    """CreateDataSource returns immediately; QuickSight validates the role
    asynchronously and lands the DataSource in CREATION_FAILED if that freshly
    created role isn't trusted yet. Poll to the terminal status and, only when this
    call is the one that just created the role, delete-and-retry on that specific
    failure until IAM propagation catches up or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    last_error_info = None
    while True:
        src = qs.create_data_source(
            AwsAccountId=account_id,
            DataSourceId=datasource_id,
            Name=datasource_id,
            Type="ATHENA",
            DataSourceParameters={"AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}},
            Tags=[{"Key": "sim2real", "Value": check_name}],
        )
        status = _poll_datasource_status(
            qs,
            account_id,
            datasource_id,
            {"CREATION_SUCCESSFUL", "CREATION_FAILED"},
            timeout_s=max(5.0, deadline - time.monotonic()),
        )
        if status == "CREATION_SUCCESSFUL":
            return src
        described = qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)[
            "DataSource"
        ]
        last_error_info = described.get("ErrorInfo")
        if not retry_on_failure or time.monotonic() >= deadline:
            raise AssertionError(
                f"data source never reached CREATION_SUCCESSFUL: {last_error_info}"
            )
        qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
        time.sleep(interval_s)


def _poll_datasource_status(qs, account_id, datasource_id, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
        last = resp["DataSource"]["Status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"data source never reached a terminal status: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
