"""deploy-function-cfn-code-s3-location-missing-object-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-function-cfn-code-s3-location-missing-object-rejected"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation", "s3"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_RUNTIME = {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"}
_FUNC_JS = (
    "export function request(ctx) { return {}; }\nexport function response(ctx) { return 'ok'; }\n"
)
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``."""
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _wait_stack(cf, stack_id: str, terminal=_TERMINAL, timeout_s: float = 600.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(cf, stack_id: str) -> None:
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def _stack_events(cf, stack_id):
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def _decisive_rows(events, *logical_ids):
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def _failed_reason(events, logical_id, status="CREATE_FAILED"):
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def _masked(text, account, *names):
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def _handler_reason(reason, account, *names):
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"], account, *names), m["code"]


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _template(api_name: str, bucket: str, key: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "GraphQLApi": {
                    "Type": "AWS::AppSync::GraphQLApi",
                    "Properties": {"Name": api_name, "AuthenticationType": "API_KEY"},
                },
                "NoneDataSource": {
                    "Type": "AWS::AppSync::DataSource",
                    "Properties": {
                        "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                        "Name": "NoneDS",
                        "Type": "NONE",
                    },
                },
                "Func1": {
                    "Type": "AWS::AppSync::FunctionConfiguration",
                    "DependsOn": ["NoneDataSource"],
                    "Properties": {
                        "ApiId": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]},
                        "Name": "Func1",
                        "DataSourceName": "NoneDS",
                        "Runtime": _RUNTIME,
                        "CodeS3Location": f"s3://{bucket}/{key}",
                    },
                },
            },
            "Outputs": {
                "ApiId": {"Value": {"Fn::GetAtt": ["GraphQLApi", "ApiId"]}},
            },
        }
    )


def _own_api(appsync, name):
    return [a for a in paginate(appsync, "list_graphql_apis", "graphqlApis") if a["name"] == name]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AppSync FunctionConfiguration whose CodeS3Location names an S3 object
    that does not exist is refused and rolls back; the same bucket with the object present
    deploys and reads the function's code back unchanged."""
    cf = ctx.client("cloudformation")
    appsync = ctx.client("appsync")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-appsync-code-rej-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_object(Bucket=bucket, Key="present.js", Body=_FUNC_JS.encode("utf-8"))

    bad_api_name = ctx.unique_name("sim2real-appsync-s3missing-api-")
    good_api_name = ctx.unique_name("sim2real-appsync-s3present-api-")

    bad_stack_id = cf.create_stack(
        StackName=ctx.unique_name("sim2real-appsync-s3missing-stk-"),
        TemplateBody=_template(bad_api_name, bucket, "missing.js"),
        Tags=[{"Key": "sim2real", "Value": bad_api_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, bad_stack_id))
    good_stack_id = cf.create_stack(
        StackName=ctx.unique_name("sim2real-appsync-s3present-stk-"),
        TemplateBody=_template(good_api_name, bucket, "present.js"),
        Tags=[{"Key": "sim2real", "Value": good_api_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, good_stack_id))

    status = _wait_stack(cf, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"rejected stack ended {status!r}: {_decisive_rows(_stack_events(cf, bad_stack_id))!r}"
    )
    reason = _failed_reason(_stack_events(cf, bad_stack_id), "Func1")
    got = _handler_reason(reason, ctx.account, bucket, bad_api_name)
    want = (
        "Error occurred during operation 'Error reading Code from S3.Error occurred during "
        "operation 'Error reading CodeS3Location from S3. Error message: The specified key "
        "does not exist. (Service: S3, Status Code: 404, Request ID: <id>, Extended Request "
        "ID: <id>) (SDK Attempt Count: <n>)'.'.",
        "GeneralServiceException",
    )
    assert got == want, f"expected handler reason {want!r}, got {got!r}"
    left = _own_api(appsync, bad_api_name)
    assert left == [], f"the rolled-back API is listed: {left!r}"

    # Positive control: the same bucket, an object that exists.
    status = _wait_stack(cf, good_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {_decisive_rows(_stack_events(cf, good_stack_id))!r}"
    )
    listed = _own_api(appsync, good_api_name)
    assert len(listed) == 1, f"expected one listed control API; got {listed!r}"
    api_id = listed[0]["apiId"]
    functions = paginate(appsync, "list_functions", "functions", apiId=api_id)
    assert len(functions) == 1, f"expected the one declared function; got {functions!r}"
    function = appsync.get_function(apiId=api_id, functionId=functions[0]["functionId"])[
        "functionConfiguration"
    ]
    assert function["code"] == _FUNC_JS, (
        f"expected the control function's code to be exactly the S3 object; got {function['code']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
