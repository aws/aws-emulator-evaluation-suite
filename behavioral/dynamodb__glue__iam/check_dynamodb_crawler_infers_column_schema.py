"""dynamodb-crawler-infers-column-schema."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dynamodb-crawler-infers-column-schema"
GROUP = "crawler-dynamodb"
SERVICES = ["dynamodb", "glue", "iam"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _glue_role_arn(ctx, table_arn: str) -> str:
    """A role Glue can assume with permission to describe and scan one DynamoDB table."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-glue-ddb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity")
    )
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.detach_role_policy(
                RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
            ),
            "NoSuchEntity",
        )
    )
    policy_name = ctx.unique_name("sim2real-xsvc-glue-ddb-scan-")
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["dynamodb:DescribeTable", "dynamodb:Scan"],
                        "Resource": table_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name), "NoSuchEntity"
        )
    )
    return role["Role"]["Arn"]


def _create_crawler_with_retry(glue, timeout_s: float = 90.0, interval_s: float = 3.0, **kwargs):
    """IAM role propagation is eventually consistent: CreateCrawler probes AssumeRole on the
    just-created role and can fail for a few seconds after AttachRolePolicy returns. Retry the
    bounded window instead of sleeping unconditionally before the role is ever exercised."""
    deadline = time.time() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidInputException" and time.time() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll(fn, pred, timeout_s, interval_s, reason):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {reason}: last value={last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A crawler targeting a DynamoDB table infers the Glue Data Catalog table's columns from
    the table's own items, and classifies it as a dynamodb data source."""
    dynamodb = ctx.client("dynamodb")
    glue = ctx.client("glue")

    table_name = ctx.unique_name("sim2real-xsvc-ddb-tbl-")
    table = dynamodb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "itemId", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "itemId", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: dynamodb.delete_table(TableName=table_name), "ResourceNotFoundException"))
    table_arn = table["TableDescription"]["TableArn"]

    waiter = dynamodb.get_waiter("table_exists")
    waiter.wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    dynamodb.put_item(
        TableName=table_name,
        Item={
            "itemId": {"S": "widget-1"},
            "quantityOnHand": {"N": "42"},
            "label": {"S": "Example Corp widget"},
        },
    )
    dynamodb.put_item(
        TableName=table_name,
        Item={
            "itemId": {"S": "widget-2"},
            "quantityOnHand": {"N": "7"},
            "label": {"S": "AnyCompany widget"},
        },
    )

    role_arn = _glue_role_arn(ctx, table_arn)

    db_name = ctx.unique_name("sim2real-xsvc-glue-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=db_name), "EntityNotFoundException"))

    crawler_name = ctx.unique_name("sim2real-xsvc-crawler-")
    _create_crawler_with_retry(
        glue,
        Name=crawler_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"DynamoDBTargets": [{"Path": table_name}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(lambda: glue.delete_crawler(Name=crawler_name), "EntityNotFoundException"))

    glue.start_crawler(Name=crawler_name)

    _poll(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"]["State"],
        lambda state: state == "READY",
        timeout_s=280.0,
        interval_s=5.0,
        reason="the crawler to return to READY",
    )

    crawler = glue.get_crawler(Name=crawler_name)["Crawler"]
    last_crawl_status = crawler["LastCrawl"]["Status"]
    assert last_crawl_status == "SUCCEEDED", (
        f"expected LastCrawl.Status SUCCEEDED, got {last_crawl_status!r} "
        f"(ErrorMessage={crawler['LastCrawl'].get('ErrorMessage')!r})"
    )

    # The crawler derives the Glue table name from the DynamoDB table name, replacing every
    # hyphen with an underscore to satisfy the catalog's naming rules.
    catalog_table_name = table_name.replace("-", "_")
    ctx.on_cleanup(
        _teardown(
            lambda: glue.delete_table(DatabaseName=db_name, Name=catalog_table_name),
            "EntityNotFoundException",
        )
    )

    table_desc = glue.get_table(DatabaseName=db_name, Name=catalog_table_name)["Table"]
    column_names = {c["Name"] for c in table_desc["StorageDescriptor"]["Columns"]}
    assert column_names == {"itemid", "quantityonhand", "label"}, (
        f"expected columns itemid, quantityonhand and label from the table's own items, "
        f"got {sorted(column_names)!r}"
    )
    assert table_desc["StorageDescriptor"]["Location"] == table_arn, (
        f"expected the catalog table's Location to be the DynamoDB table's own ARN "
        f"{table_arn!r}, got {table_desc['StorageDescriptor']['Location']!r}"
    )
    params = table_desc["Parameters"]
    assert params["classification"] == "dynamodb", (
        f"expected Parameters.classification 'dynamodb', got {params.get('classification')!r}"
    )
    assert params["recordCount"] == "2", (
        f"expected Parameters.recordCount '2' for the two items this check put, got {params.get('recordCount')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
