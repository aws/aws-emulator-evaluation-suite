"""refresh-schedule-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "refresh-schedule-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["quicksight"]

# Amazon Quick Sight allows at most five refresh schedules per dataset:
# https://docs.aws.amazon.com/quick/latest/userguide/refreshing-imported-data.html
_MAX_SCHEDULES_PER_DATASET = 5


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A dataset can hold at most five refresh schedules; the sixth CreateRefreshSchedule
    call is rejected with LimitExceededException, no sixth schedule is persisted, and
    freeing up a slot lets a new schedule be created again (positive control)."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn = _ensure_quicksight_service_role(ctx)
    datasource_id = ctx.unique_name("s2r-quota-src-")
    dataset_id = ctx.unique_name("s2r-quota-ds-")

    src = qs.create_data_source(
        AwsAccountId=account_id,
        DataSourceId=datasource_id,
        Name=datasource_id,
        Type="ATHENA",
        DataSourceParameters={"AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    )
    src_status = _poll_datasource_status(
        qs, account_id, datasource_id, {"CREATION_SUCCESSFUL", "CREATION_FAILED"}
    )
    if src_status != "CREATION_SUCCESSFUL":
        described = qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)[
            "DataSource"
        ]
        raise AssertionError(
            f"expected CREATION_SUCCESSFUL, got {src_status}: {described.get('ErrorInfo')}"
        )

    qs.create_data_set(
        AwsAccountId=account_id,
        DataSetId=dataset_id,
        Name=dataset_id,
        ImportMode="SPICE",
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: qs.delete_data_set(AwsAccountId=account_id, DataSetId=dataset_id))

    schedules = [
        {
            "ScheduleId": ctx.unique_name("s2r-sch-daily1-"),
            "ScheduleFrequency": {"Interval": "DAILY", "TimeOfTheDay": "01:00", "Timezone": "UTC"},
        },
        {
            "ScheduleId": ctx.unique_name("s2r-sch-daily2-"),
            "ScheduleFrequency": {"Interval": "DAILY", "TimeOfTheDay": "13:00", "Timezone": "UTC"},
        },
        {
            "ScheduleId": ctx.unique_name("s2r-sch-daily3-"),
            "ScheduleFrequency": {"Interval": "DAILY", "TimeOfTheDay": "18:00", "Timezone": "UTC"},
        },
        {
            "ScheduleId": ctx.unique_name("s2r-sch-weekly-"),
            "ScheduleFrequency": {
                "Interval": "WEEKLY",
                "RefreshOnDay": {"DayOfWeek": "MONDAY"},
                "TimeOfTheDay": "02:00",
                "Timezone": "UTC",
            },
        },
        {
            "ScheduleId": ctx.unique_name("s2r-sch-monthly-"),
            "ScheduleFrequency": {
                "Interval": "MONTHLY",
                "RefreshOnDay": {"DayOfMonth": "1"},
                "TimeOfTheDay": "03:00",
                "Timezone": "UTC",
            },
        },
    ]
    assert len(schedules) == _MAX_SCHEDULES_PER_DATASET

    created_ids = []
    for sched in schedules:
        qs.create_refresh_schedule(
            AwsAccountId=account_id,
            DataSetId=dataset_id,
            Schedule={**sched, "RefreshType": "FULL_REFRESH"},
        )
        created_ids.append(sched["ScheduleId"])

    sixth_id = ctx.unique_name("s2r-sch-sixth-")
    err = _client_error(
        lambda: qs.create_refresh_schedule(
            AwsAccountId=account_id,
            DataSetId=dataset_id,
            Schedule={
                "ScheduleId": sixth_id,
                "ScheduleFrequency": {
                    "Interval": "MONTHLY",
                    "RefreshOnDay": {"DayOfMonth": "2"},
                    "TimeOfTheDay": "04:00",
                    "Timezone": "UTC",
                },
                "RefreshType": "FULL_REFRESH",
            },
        )
    )
    assert err["Code"] == "LimitExceededException", err
    dataset_arn = f"arn:aws:quicksight:{ctx.region}:{account_id}:dataset/{dataset_id}"
    assert err["Message"] == (
        f"Reached max limit of {_MAX_SCHEDULES_PER_DATASET} refresh schedules for "
        f"preparedDataSource {dataset_arn}"
    ), err

    # effect absent: the sixth schedule was never persisted
    listed = qs.list_refresh_schedules(AwsAccountId=account_id, DataSetId=dataset_id)[
        "RefreshSchedules"
    ]
    listed_ids = {s["ScheduleId"] for s in listed}
    assert sixth_id not in listed_ids, listed_ids
    assert listed_ids == set(created_ids), listed_ids

    # positive control: free a slot, then creating a new schedule succeeds again
    qs.delete_refresh_schedule(
        AwsAccountId=account_id, DataSetId=dataset_id, ScheduleId=created_ids[0]
    )
    qs.create_refresh_schedule(
        AwsAccountId=account_id,
        DataSetId=dataset_id,
        Schedule={
            "ScheduleId": sixth_id,
            "ScheduleFrequency": {
                "Interval": "MONTHLY",
                "RefreshOnDay": {"DayOfMonth": "2"},
                "TimeOfTheDay": "04:00",
                "Timezone": "UTC",
            },
            "RefreshType": "FULL_REFRESH",
        },
    )
    listed_after = qs.list_refresh_schedules(AwsAccountId=account_id, DataSetId=dataset_id)[
        "RefreshSchedules"
    ]
    assert sixth_id in {s["ScheduleId"] for s in listed_after}


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected AWS to reject this call, but it SUCCEEDED and returned {result!r}")


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
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except Exception:
            pass

    return role_arn


def _poll_datasource_status(qs, account_id, datasource_id, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    """CreateDataSource returns before the connection is actually validated (it starts in
    CREATION_IN_PROGRESS, including while the just-created execution role is still propagating
    to the assume-role check QuickSight performs); the real outcome — including a role that
    hasn't propagated yet — only shows up once DescribeDataSource reaches a terminal status."""
    import time

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
