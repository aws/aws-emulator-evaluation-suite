"""dataset-spice-ingestion-fails-deterministically-on-invalid-source."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataset-spice-ingestion-fails-deterministically-on-invalid-source"
GROUP = "data-plane"
SERVICES = ["quicksight"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Athena data source on a nonexistent workgroup ends CREATION_FAILED with a
    workgroup-specific ErrorInfo and CreateDataSet on it fails with
    InvalidParameterValueException; the same source on "primary" succeeds."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn = _ensure_quicksight_service_role(ctx)

    good = _create_athena_data_source_until_conclusive(qs, ctx, account_id, "primary", role_arn)
    assert good["Status"] == "CREATION_SUCCESSFUL", (
        f"positive control failed: a data source against the account's real 'primary' "
        f"Athena workgroup must succeed, or the negative below proves nothing: {good}"
    )

    bogus_workgroup = ctx.unique_name("s2r-no-such-wg-")
    bad = _create_athena_data_source_until_conclusive(qs, ctx, account_id, bogus_workgroup, role_arn)
    assert bad["Status"] == "CREATION_FAILED", bad
    error_info = bad.get("ErrorInfo")
    assert error_info is not None, bad
    error_type = error_info.get("Type")
    assert error_type, error_info
    assert error_type not in _ROLE_NOT_READY_ERROR_TYPES, (
        f"data source failed on IAM role readiness ({error_type}), never exercising the "
        f"invalid-workgroup contract under test: {error_info}"
    )
    assert error_type == "GENERIC_SQL_FAILURE", error_info
    # message varies: ErrorInfo.Message embeds the per-call Athena request id, so only its
    # subject is checked here.
    message = (error_info.get("Message") or "").lower()
    assert "workgroup" in message, (
        f"expected the failure to name the missing workgroup, got: {error_info}"
    )

    dataset_id = ctx.unique_name("s2r-athena-ds-")

    def _cleanup_dataset() -> None:
        try:
            qs.delete_data_set(AwsAccountId=account_id, DataSetId=dataset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_dataset)
    error = _client_error(
        lambda: qs.create_data_set(
            AwsAccountId=account_id,
            DataSetId=dataset_id,
            Name=dataset_id,
            ImportMode="SPICE",
            PhysicalTableMap={
                "tbl1": {
                    "CustomSql": {
                        "DataSourceArn": bad["Arn"],
                        "Name": "q1",
                        "SqlQuery": "SELECT 1 AS col",
                        "Columns": [{"Name": "col", "Type": "INTEGER"}],
                    }
                }
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert error.get("Code") == "InvalidParameterValueException", error
    assert error.get("Message") == f"DataSource {bad['Arn']} is in status CREATION_FAILED", error


#: The freshly created execution role can take a few seconds to become assumable by
#: QuickSight; until it does, the data source's own connection test fails on the role
#: instead of on the workgroup this check targets.
_ROLE_NOT_READY_ERROR_TYPES = frozenset({"ACCESS_DENIED"})


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS accepted this call, but it should have been refused: {result!r}")


def _create_athena_data_source_until_conclusive(qs, ctx, account_id, workgroup, role_arn, role_readiness_budget_s=90.0):
    """Create an Athena data source and poll it to a terminal Status. Retry -- never
    sleep -- while the ONLY failure seen is role readiness (ErrorInfo.Type ==
    ACCESS_DENIED), bounded by role_readiness_budget_s."""
    deadline = time.monotonic() + role_readiness_budget_s
    while True:
        datasource_id = ctx.unique_name("s2r-athena-src-")
        qs.create_data_source(
            AwsAccountId=account_id,
            DataSourceId=datasource_id,
            Name=datasource_id,
            Type="ATHENA",
            DataSourceParameters={"AthenaParameters": {"WorkGroup": workgroup, "RoleArn": role_arn}},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(
            lambda did=datasource_id: qs.delete_data_source(AwsAccountId=account_id, DataSourceId=did)
        )
        ds = _poll_data_source_terminal(qs, account_id, datasource_id, timeout_s=120.0)
        if (
            ds["Status"] != "CREATION_FAILED"
            or ds.get("ErrorInfo", {}).get("Type") not in _ROLE_NOT_READY_ERROR_TYPES
            or time.monotonic() >= deadline
        ):
            return ds
        time.sleep(5.0)


def _poll_data_source_terminal(qs, account_id, datasource_id, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    terminal = {"CREATION_SUCCESSFUL", "CREATION_FAILED"}
    while time.monotonic() < deadline:
        resp = qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
        last = resp["DataSource"]
        if last["Status"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"data source never reached a terminal status: {last}")


def _ensure_quicksight_subscribed(qs, account_id) -> None:
    """QuickSight requires a one-time account subscription before any resource
    operation succeeds: create it (ENTERPRISE / IAM_ONLY) when the account has none
    and wait for ACCOUNT_CREATED."""
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
    its ARN through AthenaParameters.RoleArn; returns the ARN. A fresh role is not yet
    assumable, so the caller retries data source creation."""
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
