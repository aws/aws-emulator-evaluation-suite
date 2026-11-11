"""dataset-direct-query-import-mode-skips-ingestion."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "dataset-direct-query-import-mode-skips-ingestion"
GROUP = "data-plane"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataSet with ImportMode=DIRECT_QUERY mints no IngestionId, while the same dataset with
    ImportMode=SPICE does."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn = _ensure_quicksight_service_role(ctx)
    datasource_id = ctx.unique_name("s2r-dq-src-")
    dataset_id = ctx.unique_name("s2r-dq-ds-")
    spice_dataset_id = ctx.unique_name("s2r-dq-spice-ds-")

    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    src = _create_data_source_with_retry(qs, account_id, datasource_id, role_arn, resource_tags)
    ctx.on_cleanup(
        lambda: qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    )
    datasource_arn = src["Arn"]

    def physical_table_map(name: str) -> dict:
        return {
            "tbl1": {
                "CustomSql": {
                    "DataSourceArn": datasource_arn,
                    "Name": name,
                    "SqlQuery": "SELECT 1 AS col",
                    "Columns": [{"Name": "col", "Type": "INTEGER"}],
                }
            }
        }

    created = qs.create_data_set(
        AwsAccountId=account_id,
        DataSetId=dataset_id,
        Name=dataset_id,
        ImportMode="DIRECT_QUERY",
        PhysicalTableMap=physical_table_map("q1"),
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: qs.delete_data_set(AwsAccountId=account_id, DataSetId=dataset_id))

    assert "IngestionId" not in created, f"DIRECT_QUERY minted an ingestion: {created}"
    assert "IngestionArn" not in created, f"DIRECT_QUERY minted an ingestion: {created}"

    described = qs.describe_data_set(AwsAccountId=account_id, DataSetId=dataset_id)["DataSet"]
    assert described["ImportMode"] == "DIRECT_QUERY", described

    # Positive control, same wiring, same run: SPICE on the identical data source DOES
    # mint an ingestion. Without this, a target that never mints an ingestion for any
    # import mode would score this check green too.
    spice_created = qs.create_data_set(
        AwsAccountId=account_id,
        DataSetId=spice_dataset_id,
        Name=spice_dataset_id,
        ImportMode="SPICE",
        PhysicalTableMap=physical_table_map("q2"),
        Tags=resource_tags,
    )
    ctx.on_cleanup(
        lambda: qs.delete_data_set(AwsAccountId=account_id, DataSetId=spice_dataset_id)
    )
    assert "IngestionId" in spice_created, f"SPICE did not mint an ingestion: {spice_created}"
    assert "IngestionArn" in spice_created, f"SPICE did not mint an ingestion: {spice_created}"

    spice_described = qs.describe_data_set(
        AwsAccountId=account_id, DataSetId=spice_dataset_id
    )["DataSet"]
    assert spice_described["ImportMode"] == "SPICE", spice_described


def _ensure_quicksight_subscribed(qs, account_id) -> None:
    """QuickSight requires a one-time account subscription before any resource
    operation succeeds: create it (ENTERPRISE / IAM_ONLY) when the account has none
    and wait for ACCOUNT_CREATED."""
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
    which the API can't do). Create an equivalent role idempotently via IAM and pass
    its ARN through AthenaParameters.RoleArn, so ATHENA data sources can be created
    through the API alone. Returns the role's ARN."""
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


def _create_data_source_with_retry(
    qs, account_id, datasource_id, role_arn, resource_tags, timeout_s=90.0
):
    """CreateDataSource returns synchronously with the data source in
    CREATION_IN_PROGRESS; QuickSight then validates AthenaParameters.RoleArn against IAM
    asynchronously, and a just-created role's trust policy has not always propagated by
    the time that validation runs, landing the data source in CREATION_FAILED. Poll for
    the terminal status with a deadline and, on a trust-propagation failure specifically,
    delete the failed data source and retry the whole create."""
    import time

    deadline = time.monotonic() + timeout_s
    last_error_info = None
    while time.monotonic() < deadline:
        qs.create_data_source(
            AwsAccountId=account_id,
            DataSourceId=datasource_id,
            Name=datasource_id,
            Type="ATHENA",
            DataSourceParameters={
                "AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}
            },
            Tags=resource_tags,
        )
        while time.monotonic() < deadline:
            src = qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)[
                "DataSource"
            ]
            status = src["Status"]
            if status == "CREATION_SUCCESSFUL":
                return src
            if status == "CREATION_FAILED":
                break
            time.sleep(3.0)
        else:
            raise AssertionError(f"data source {datasource_id} never reached a terminal status")

        error_info = src.get("ErrorInfo") or {}
        last_error_info = error_info
        message = (error_info.get("Message") or "").lower()
        if "role" in message or "assume" in message or "permission" in message:
            qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
            time.sleep(5.0)
            continue
        raise AssertionError(f"data source creation failed: {error_info}")
    raise AssertionError(
        f"data source never became usable after retrying the service-role trust "
        f"failure: {last_error_info}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
