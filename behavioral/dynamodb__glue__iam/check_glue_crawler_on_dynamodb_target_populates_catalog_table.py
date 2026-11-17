"""glue-crawler-on-dynamodb-target-populates-catalog-table."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-on-dynamodb-target-populates-catalog-table"
GROUP = "catalog-ingestion"
SERVICES = ["dynamodb", "glue", "iam"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
}
_GLUE_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _table_policy(table_arn: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                        "Action": ["dynamodb:DescribeTable", "dynamodb:Scan"],
                        "Resource": table_arn}],
    })


def _wait_table_active(ddb, name: str, *, budget_s: float = 120.0) -> str:
    deadline = time.monotonic() + budget_s
    while True:
        desc = ddb.describe_table(TableName=name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc["TableArn"]
        assert time.monotonic() < deadline, f"table {name!r} never reached ACTIVE: {desc['TableStatus']!r}"
        time.sleep(3)


def _wait_crawler_ready(glue, name: str, *, budget_s: float = 420.0) -> dict:
    """Poll GetCrawler to the terminal READY state and return its LastCrawl info."""
    deadline = time.monotonic() + budget_s
    while True:
        crawler = glue.get_crawler(Name=name)["Crawler"]
        if crawler["State"] == "READY":
            return crawler["LastCrawl"]
        assert time.monotonic() < deadline, f"crawler {name!r} did not reach READY: state {crawler['State']!r}"
        time.sleep(5)


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue crawler targeting a DynamoDB table scans its items and creates a Data Catalog
    table whose columns reflect the attributes actually stored, read back through Glue."""
    ddb = ctx.client("dynamodb")
    glue = ctx.client("glue")
    iam = ctx.client("iam")

    table_name = ctx.unique_name("sim2real-xsvc-glue-ddb-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table_name), "ResourceNotFoundException"))
    table_arn = _wait_table_active(ddb, table_name)

    ddb.put_item(TableName=table_name, Item={
        "id": {"S": "row-1"}, "city": {"S": "Any Town"}, "population": {"N": "42"},
    })
    ddb.put_item(TableName=table_name, Item={
        "id": {"S": "row-2"}, "city": {"S": "Example City"}, "population": {"N": "7"},
    })

    role_name = ctx.unique_name("sim2real-xsvc-glue-ddb-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": "glue-crawler-on-dynamodb-target"}],
    )["Role"]["Arn"]

    def _delete_role() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="table-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_GLUE_SERVICE_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_teardown(_delete_role, "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_SERVICE_POLICY)
    iam.put_role_policy(RoleName=role_name, PolicyName="table-access", PolicyDocument=_table_policy(table_arn))

    db_name = ctx.unique_name("sim2real_xsvc_glue_ddb_db_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=db_name), "EntityNotFoundException"))

    crawler_name = ctx.unique_name("sim2real-xsvc-glue-ddb-crawler-")

    def _create_crawler_with_role_propagation_retry() -> None:
        deadline = time.monotonic() + 60.0
        while True:
            try:
                glue.create_crawler(
                    Name=crawler_name, Role=role_arn, DatabaseName=db_name,
                    Targets={"DynamoDBTargets": [{"Path": table_name}]},
                )
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() > deadline:
                    raise
                time.sleep(5)

    _create_crawler_with_role_propagation_retry()
    ctx.on_cleanup(_teardown(lambda: glue.delete_crawler(Name=crawler_name), "EntityNotFoundException"))

    glue.start_crawler(Name=crawler_name)
    last_crawl = _wait_crawler_ready(glue, crawler_name)
    assert last_crawl["Status"] == "SUCCEEDED", (
        f"crawl finished {last_crawl['Status']!r}, expected SUCCEEDED: {last_crawl.get('ErrorMessage')!r}"
    )

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) == 1, f"expected exactly one catalog table from the crawl, found {len(tables)}: {tables!r}"
    catalog_table = tables[0]
    assert catalog_table["StorageDescriptor"]["Location"] == table_arn, (
        f"catalog table location {catalog_table['StorageDescriptor']['Location']!r}, expected the "
        f"DynamoDB table's own ARN {table_arn!r}"
    )
    columns = {c["Name"]: c["Type"] for c in catalog_table["StorageDescriptor"]["Columns"]}
    assert "id" in columns, f"catalog columns {sorted(columns)} are missing the partition key 'id'"
    assert "city" in columns and "population" in columns, (
        f"catalog columns {sorted(columns)} are missing attributes scanned from the table's items"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
