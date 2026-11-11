"""datasource-lifecycle-create-update-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "datasource-lifecycle-create-update-delete"
GROUP = "state-machine"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A data source moves CREATION_IN_PROGRESS -> CREATION_SUCCESSFUL, an UpdateDataSource
    call that only changes the display Name settles on UPDATE_SUCCESSFUL and the new
    name is visible, and after DeleteDataSource the resource is gone."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn = _ensure_quicksight_service_role(ctx)
    datasource_id = ctx.unique_name("s2r-lifecycle-src-")

    ctx.on_cleanup(lambda: _best_effort_delete(qs, account_id, datasource_id))
    _create_data_source_until_role_ready(
        qs,
        account_id,
        datasource_id,
        dict(
            AwsAccountId=account_id,
            DataSourceId=datasource_id,
            Name=datasource_id,
            Type="ATHENA",
            DataSourceParameters={"AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}},
            Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        ),
    )

    new_name = datasource_id + "-renamed"
    qs.update_data_source(
        AwsAccountId=account_id,
        DataSourceId=datasource_id,
        Name=new_name,
        DataSourceParameters={"AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}},
    )
    status_after_update = _poll_datasource_status(
        qs, account_id, datasource_id, {"UPDATE_SUCCESSFUL", "UPDATE_FAILED"}
    )
    assert status_after_update == "UPDATE_SUCCESSFUL", status_after_update

    described = qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)[
        "DataSource"
    ]
    assert described["Name"] == new_name, described

    qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    source_gone = (
        f"DataSource arn:aws:quicksight:{ctx.region}:{account_id}:datasource/{datasource_id} "
        "is not found"
    )
    err = _client_error(
        lambda: qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    )
    assert err["Code"] == "ResourceNotFoundException", err
    assert err["Message"] == source_gone, err

    mutate_err = _client_error(
        lambda: qs.update_data_source(
            AwsAccountId=account_id,
            DataSourceId=datasource_id,
            Name=new_name,
            DataSourceParameters={"AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}},
        )
    )
    assert mutate_err["Code"] == "ResourceNotFoundException", mutate_err
    assert mutate_err["Message"] == source_gone, mutate_err


def _best_effort_delete(qs, account_id, datasource_id) -> None:
    from botocore.exceptions import ClientError

    try:
        qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected AWS to reject this call, but it SUCCEEDED and returned {result!r}")


def _create_data_source_until_role_ready(qs, account_id, datasource_id, create_kwargs, timeout_s=120.0, interval_s=10.0):
    """A just-created IAM role is not immediately assumable by QuickSight: CreateDataSource
    accepts the request, but the async provisioning then settles on CREATION_FAILED with
    ErrorInfo.Type == ACCESS_DENIED ("Failed to assume your role") until the role has
    propagated. Delete the failed attempt and retry the whole create-to-terminal cycle,
    bounded by a deadline, rather than sleeping before the first attempt regardless of
    whether the role is old or new. Any other terminal failure is raised immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        qs.create_data_source(**create_kwargs)
        status = _poll_datasource_status(qs, account_id, datasource_id, {"CREATION_SUCCESSFUL", "CREATION_FAILED"})
        if status == "CREATION_SUCCESSFUL":
            return
        error_info = qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)[
            "DataSource"
        ].get("ErrorInfo") or {}
        if error_info.get("Type") != "ACCESS_DENIED" or time.monotonic() >= deadline:
            raise AssertionError(f"expected CREATION_SUCCESSFUL, got {status}: {error_info}")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
