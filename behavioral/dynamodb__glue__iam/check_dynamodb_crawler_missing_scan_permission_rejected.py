"""dynamodb-crawler-missing-scan-permission-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dynamodb-crawler-missing-scan-permission-rejected"
GROUP = "crawler-dynamodb"
SERVICES = ["dynamodb", "glue", "iam"]

_GLUE_SERVICE_ROLE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_REQUEST_ID_RE = re.compile(r"Request ID: ([A-Z0-9]+);")


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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_crawler_until_stable(glue, timeout_s: float = 120.0, interval_s: float = 3.0, **kwargs):
    """CreateCrawler can transiently refuse while the role's trust policy or a just-attached
    permission is still propagating; retry the bounded window and return the error only once it
    has held for the whole window (or return once the call succeeds)."""
    deadline = time.time() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            return None, None
        except ClientError as exc:
            err = exc.response.get("Error", {})
            message = err.get("Message", "")
            retryable = "unable to assume provided role" in message or "is not authorized to perform" in message
            if err.get("Code") == "InvalidInputException" and retryable and time.time() < deadline:
                time.sleep(interval_s)
                continue
            return err.get("Code"), err.get("Message")


def _poll(fn, pred, timeout_s, interval_s, reason):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {reason}: last value={last!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCrawler refuses a DynamoDB target when the role cannot DescribeTable it, creating
    no crawler and no catalog table; granting dynamodb:DescribeTable and dynamodb:Scan lets the
    identical call succeed and the resulting crawl populate the catalog."""
    iam = ctx.client("iam")
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
    dynamodb.put_item(TableName=table_name, Item={"itemId": {"S": "widget-1"}, "label": {"S": "Example Corp widget"}})

    role_name = ctx.unique_name("sim2real-xsvc-glue-ddb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_SERVICE_ROLE_POLICY)
    ctx.on_cleanup(
        _teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_GLUE_SERVICE_ROLE_POLICY), "NoSuchEntity")
    )

    db_name = ctx.unique_name("sim2real-xsvc-glue-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=db_name), "EntityNotFoundException"))

    crawler_name = ctx.unique_name("sim2real-xsvc-crawler-")
    targets = {"DynamoDBTargets": [{"Path": table_name}]}
    catalog_table_name = table_name.replace("-", "_")

    code, message = _create_crawler_until_stable(
        glue, Name=crawler_name, Role=role_arn, DatabaseName=db_name, Targets=targets, Tags={"sim2real": CHECK}
    )
    assert code == "InvalidInputException", (
        f"expected CreateCrawler to refuse a role with no dynamodb:DescribeTable, got code {code!r}: {message!r}"
    )
    match = _REQUEST_ID_RE.search(message or "")
    assert match, f"expected an embedded Request ID in the message, got {message!r}"
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/AWS-Crawler is not authorized "
        f"to perform: dynamodb:DescribeTable on resource: {table_arn} because no identity-based "
        "policy allows the dynamodb:DescribeTable action (Service: AmazonDynamoDBv2; Status Code: "
        f"400; Error Code: AccessDeniedException; Request ID: {match.group(1)}; Proxy: null)"
    )
    assert message == expected_message, f"unexpected message {message!r}"

    # The refused CreateCrawler leaves neither a crawler nor a catalog table behind.
    code, message = _error(lambda: glue.get_crawler(Name=crawler_name))
    assert code == "EntityNotFoundException", f"expected no crawler to have been created, got {code}: {message!r}"
    code, message = _error(lambda: glue.get_table(DatabaseName=db_name, Name=catalog_table_name))
    assert code == "EntityNotFoundException", f"expected no catalog table to have been created, got {code}: {message!r}"
    assert message == "Entity Not Found", f"unexpected GetTable message {message!r}"

    scan_policy_name = ctx.unique_name("sim2real-xsvc-glue-ddb-scan-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=scan_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["dynamodb:DescribeTable", "dynamodb:Scan"], "Resource": table_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=scan_policy_name), "NoSuchEntity"))

    code, message = _create_crawler_until_stable(
        glue, Name=crawler_name, Role=role_arn, DatabaseName=db_name, Targets=targets, Tags={"sim2real": CHECK}
    )
    assert code is None, f"expected the identical CreateCrawler to succeed once permission was granted, got {code}: {message!r}"
    ctx.on_cleanup(_teardown(lambda: glue.delete_crawler(Name=crawler_name), "EntityNotFoundException"))

    glue.start_crawler(Name=crawler_name)
    _poll(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"]["State"],
        lambda state: state == "READY",
        timeout_s=280.0,
        interval_s=5.0,
        reason="the crawler to return to READY once permission was granted",
    )
    granted_crawl = glue.get_crawler(Name=crawler_name)["Crawler"]["LastCrawl"]
    assert granted_crawl["Status"] == "SUCCEEDED", (
        f"expected LastCrawl.Status SUCCEEDED once dynamodb:Scan was granted, got {granted_crawl['Status']!r} "
        f"(ErrorMessage={granted_crawl.get('ErrorMessage')!r})"
    )
    ctx.on_cleanup(
        _teardown(lambda: glue.delete_table(DatabaseName=db_name, Name=catalog_table_name), "EntityNotFoundException")
    )
    table_desc = glue.get_table(DatabaseName=db_name, Name=catalog_table_name)["Table"]
    assert table_desc["Parameters"]["classification"] == "dynamodb", (
        f"expected the recovered crawl to classify the table as dynamodb, got {table_desc['Parameters'].get('classification')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
