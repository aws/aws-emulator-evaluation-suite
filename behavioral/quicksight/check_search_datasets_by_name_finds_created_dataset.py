"""search-datasets-by-name-finds-created-dataset."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-datasets-by-name-finds-created-dataset"
GROUP = "state"
SERVICES = ["quicksight"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchDataSets with a DATASET_NAME/StringLike filter eventually finds a freshly
    created dataset by its unique name substring, and stops finding it after the
    dataset is deleted."""
    qs = ctx.client("quicksight")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_quicksight_subscribed(qs, account_id)
    role_arn = _ensure_quicksight_service_role(ctx)
    datasource_id = ctx.unique_name("s2r-search-src-")
    dataset_id = ctx.unique_name("s2r-search-ds-")
    dataset_name = ctx.unique_name("s2r-searchable-name-")

    src = _create_data_source_with_role_propagation_retry(
        qs,
        AwsAccountId=account_id,
        DataSourceId=datasource_id,
        Name=datasource_id,
        Type="ATHENA",
        DataSourceParameters={"AthenaParameters": {"WorkGroup": "primary", "RoleArn": role_arn}},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: qs.delete_data_source(AwsAccountId=account_id, DataSourceId=datasource_id)
    )

    qs.create_data_set(
        AwsAccountId=account_id,
        DataSetId=dataset_id,
        Name=dataset_name,
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    filters = [{"Name": "DATASET_NAME", "Operator": "StringLike", "Value": dataset_name}]

    found = _poll_until(
        lambda: qs.search_data_sets(AwsAccountId=account_id, Filters=filters)["DataSetSummaries"],
        lambda summaries: any(s["DataSetId"] == dataset_id for s in summaries),
        timeout_s=60.0,
    )
    assert found, "created dataset never appeared in SearchDataSets"

    qs.delete_data_set(AwsAccountId=account_id, DataSetId=dataset_id)

    gone = _poll_until(
        lambda: qs.search_data_sets(AwsAccountId=account_id, Filters=filters)["DataSetSummaries"],
        lambda summaries: not any(s["DataSetId"] == dataset_id for s in summaries),
        timeout_s=60.0,
    )
    assert gone, "deleted dataset still appeared in SearchDataSets"

    from botocore.exceptions import ClientError

    dataset_gone = f"DataSet arn:aws:quicksight:{ctx.region}:{account_id}:dataset/{dataset_id} is not found"
    try:
        qs.describe_data_set(AwsAccountId=account_id, DataSetId=dataset_id)
        raise AssertionError("describe_data_set succeeded for a dataset already deleted")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        assert e.response["Error"]["Message"] == dataset_gone, e.response["Error"]

    try:
        qs.delete_data_set(AwsAccountId=account_id, DataSetId=dataset_id)
        raise AssertionError("delete_data_set succeeded twice on the same dataset id")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        assert e.response["Error"]["Message"] == dataset_gone, e.response["Error"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return True
        time.sleep(interval_s)
    return False


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
    alone. Returns the role's ARN. Assume-role propagation into QuickSight (a separate,
    unbounded delay from IAM's own control plane) is handled by the caller retrying the
    role-consuming call, not by a fixed sleep here."""
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
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSQuicksightAthenaAccess",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    return role_arn


def _create_data_source_with_role_propagation_retry(qs, timeout_s=60.0, interval_s=5.0, **kwargs):
    """A just-created IAM role is not immediately assumable by QuickSight; CreateDataSource
    can reject it for a window after creation. Retry the actual role-consuming call on a
    bounded deadline instead of guessing a fixed propagation delay up front."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while True:
        try:
            return qs.create_data_source(**kwargs)
        except ClientError as e:
            last_err = e
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateDataSource never succeeded within {timeout_s}s of the IAM role's "
                    f"creation (role propagation into QuickSight): {last_err}"
                ) from last_err
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
