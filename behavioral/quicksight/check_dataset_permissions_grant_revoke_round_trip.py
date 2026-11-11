"""dataset-permissions-grant-revoke-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "dataset-permissions-grant-revoke-round-trip"
GROUP = "data-plane"
SERVICES = ["quicksight"]

_GRANTED_ACTIONS = [
    "quicksight:DescribeDataSet",
    "quicksight:DescribeDataSetPermissions",
    "quicksight:PassDataSet",
    "quicksight:DescribeIngestion",
    "quicksight:ListIngestions",
]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataSetPermissions grants are visible on DescribeDataSetPermissions, and a
    subsequent revoke actually removes that principal's entry rather than merely
    appearing to."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn = _ensure_quicksight_service_role(ctx)
    namespace = "default"
    group_name = ctx.unique_name("s2r-perm-grp-")
    datasource_id = ctx.unique_name("s2r-perm-src-")
    dataset_id = ctx.unique_name("s2r-perm-ds-")

    group = qs.create_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)["Group"]
    ctx.on_cleanup(
        lambda: qs.delete_group(AwsAccountId=account_id, Namespace=namespace, GroupName=group_name)
    )
    group_arn = group["Arn"]

    src = _call_with_role_propagation_retry(
        lambda: qs.create_data_source(
            AwsAccountId=account_id,
            DataSourceId=datasource_id,
            Name=datasource_id,
            Type="ATHENA",
            DataSourceParameters={"AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(
        lambda: qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    )
    src_state = _poll_until(
        lambda: qs.describe_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)[
            "DataSource"
        ],
        lambda d: d["Status"] != "CREATION_IN_PROGRESS",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert src_state["Status"] == "CREATION_SUCCESSFUL", src_state

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
                    "SqlQuery": "SELECT 1 AS col",
                    "Columns": [{"Name": "col", "Type": "INTEGER"}],
                }
            }
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: qs.delete_data_set(AwsAccountId=account_id, DataSetId=dataset_id))

    before = qs.describe_data_set_permissions(AwsAccountId=account_id, DataSetId=dataset_id)[
        "Permissions"
    ]
    assert not any(p["Principal"] == group_arn for p in before), before

    qs.update_data_set_permissions(
        AwsAccountId=account_id,
        DataSetId=dataset_id,
        GrantPermissions=[{"Principal": group_arn, "Actions": _GRANTED_ACTIONS}],
    )
    after_grant = qs.describe_data_set_permissions(AwsAccountId=account_id, DataSetId=dataset_id)[
        "Permissions"
    ]
    matching = [p for p in after_grant if p["Principal"] == group_arn]
    assert len(matching) == 1, after_grant
    assert set(matching[0]["Actions"]) == set(_GRANTED_ACTIONS), matching[0]

    qs.update_data_set_permissions(
        AwsAccountId=account_id,
        DataSetId=dataset_id,
        RevokePermissions=[{"Principal": group_arn, "Actions": _GRANTED_ACTIONS}],
    )
    after_revoke = qs.describe_data_set_permissions(AwsAccountId=account_id, DataSetId=dataset_id)[
        "Permissions"
    ]
    assert not any(p["Principal"] == group_arn for p in after_revoke), after_revoke


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


def _call_with_role_propagation_retry(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
    """A just-created IAM role is not always immediately assumable by another AWS
    service; retry the caller-supplied call on that specific transient rejection
    until it clears or the deadline expires."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    last_err = None
    while _time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidParameterValueException"):
                last_err = err
                _time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "retry loop exited without ever calling fn()"
    raise last_err


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    """Bounded retry for a genuinely asynchronous AWS state transition. Raises on
    timeout rather than returning the last (possibly still-pending) observation."""
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last = None
    while _time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        _time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for condition; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
