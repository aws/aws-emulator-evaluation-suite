"""glue-crawler-missing-table-scan-permission-fails-crawl."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-missing-table-scan-permission-fails-crawl"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "glue", "iam"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
}
_GLUE_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_REQUEST_ID = re.compile(r"Request ID: [^;]+;")


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


def _create_crawler(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) CreateCrawler raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("CreateCrawler unexpectedly SUCCEEDED for a role with no table permission")


def _without_request_id(message: str) -> str:
    """``message`` with its AWS SDK ``Request ID: ...;`` segment normalised away."""
    return _REQUEST_ID.sub("Request ID: <id>;", message)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCrawler on a DynamoDB target refuses a role that cannot DescribeTable the target,
    naming that one denial, and creates no crawler; granting the permission makes it succeed."""
    ddb = ctx.client("dynamodb")
    glue = ctx.client("glue")
    iam = ctx.client("iam")

    table_name = ctx.unique_name("sim2real-xsvc-glue-ddb-deny-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table_name), "ResourceNotFoundException"))
    table_arn = _wait_table_active(ddb, table_name)
    ddb.put_item(TableName=table_name, Item={"id": {"S": "row-1"}, "note": {"S": "Any Street"}})

    role_name = ctx.unique_name("sim2real-xsvc-glue-ddb-deny-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": "glue-crawler-missing-table-scan-permission"}],
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
    # The role trusts Glue and can log, but was deliberately never granted a single table
    # permission: this is the one thing broken.

    db_name = ctx.unique_name("sim2real_xsvc_glue_ddb_deny_db_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=db_name), "EntityNotFoundException"))

    crawler_name = ctx.unique_name("sim2real-xsvc-glue-ddb-deny-crawler-")

    def _attempt() -> None:
        glue.create_crawler(
            Name=crawler_name, Role=role_arn, DatabaseName=db_name,
            Targets={"DynamoDBTargets": [{"Path": table_name}]},
        )

    # IAM role propagation: the very first CreateCrawler on a brand-new role can also see
    # "Service is unable to assume provided role" while the trust policy is still propagating;
    # retry that one transient shape only, never the denial being asserted below.
    deadline = time.monotonic() + 60.0
    while True:
        code, message = _create_crawler(_attempt)
        if code != "InvalidInputException" or "unable to assume provided role" not in message:
            break
        assert time.monotonic() < deadline, f"role assumption kept failing: {message!r}"
        time.sleep(5)

    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}: {message!r}"
    assumed_role_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/AWS-Crawler"
    expected_message = _without_request_id(
        f"User: {assumed_role_arn} is not authorized to perform: dynamodb:DescribeTable on "
        f"resource: {table_arn} because no identity-based policy allows the "
        f"dynamodb:DescribeTable action (Service: AmazonDynamoDBv2; Status Code: 400; Error "
        f"Code: AccessDeniedException; Request ID: <id>; Proxy: null)"
    )
    assert _without_request_id(message) == expected_message, (
        f"CreateCrawler denial message was {message!r}, expected (Request ID excluded) "
        f"{expected_message!r}"
    )

    assert glue.get_tables(DatabaseName=db_name)["TableList"] == [], (
        "a catalog table exists even though CreateCrawler was refused"
    )

    iam.put_role_policy(RoleName=role_name, PolicyName="table-access", PolicyDocument=_table_policy(table_arn))

    def _create_with_permission_propagation_retry() -> None:
        deadline = time.monotonic() + 90.0
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

    _create_with_permission_propagation_retry()
    ctx.on_cleanup(_teardown(lambda: glue.delete_crawler(Name=crawler_name), "EntityNotFoundException"))

    glue.start_crawler(Name=crawler_name)
    restored_crawl = _wait_crawler_ready(glue, crawler_name)
    assert restored_crawl["Status"] == "SUCCEEDED", (
        f"crawl after granting the permission finished {restored_crawl['Status']!r}, expected "
        f"SUCCEEDED: {restored_crawl.get('ErrorMessage')!r}"
    )

    tables_after = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables_after) == 1, (
        f"expected exactly one catalog table once the permission was granted, found "
        f"{len(tables_after)}: {tables_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
