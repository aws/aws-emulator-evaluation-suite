"""sam-graphqlapi-round-trip-and-removed-on-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-graphqlapi-round-trip-and-removed-on-delete"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack_via_change_set(ctx, cf, name, template, capabilities, timeout_s=300.0):
    """Deploy a Transform (SAM) template as `sam deploy` does: CREATE change set, execute, wait.

    Returns ``(stack_id, change_set, stack_status)``; a FAILED change set is not executed
    (status None), so the check grades ``change_set["StatusReason"]``. Cleanup is registered first.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    resp = cf.create_change_set(
        StackName=name, ChangeSetName="sim2real-create", ChangeSetType="CREATE",
        TemplateBody=template, Capabilities=list(capabilities),
        Tags=[{"Key": "sim2real", "Value": name}],
    )
    stack_id, change_set_id = resp["StackId"], resp["Id"]
    created["StackId"] = stack_id
    deadline = time.monotonic() + timeout_s
    while True:
        change_set = cf.describe_change_set(ChangeSetName=change_set_id)
        if change_set["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"change set {change_set_id} still {change_set['Status']!r}")
        time.sleep(2)
    if change_set["Status"] == "FAILED":
        return stack_id, change_set, None
    cf.execute_change_set(ChangeSetName=change_set_id)
    return stack_id, change_set, wait_stack(cf, stack_id, timeout_s=timeout_s)


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_CAPS = ["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"]
_RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
_API_GONE = ("NotFoundException", "API not found.")

_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Api:
    Type: AWS::Serverless::GraphQLApi
    Properties:
      Name: __API_NAME__
      SchemaInline: |
        type Query {
          ping: String
        }
      Auth:
        Type: AWS_IAM
      Functions:
        pingFn:
          Runtime:
            Name: APPSYNC_JS
            Version: "1.0.0"
          DataSource: NONE
          CodeUri: "s3://__CODE_BUCKET__/pingFn.js"
      Resolvers:
        Query:
          ping:
            Runtime:
              Name: APPSYNC_JS
              Version: "1.0.0"
            CodeUri: "s3://__CODE_BUCKET__/pingResolver.js"
            Pipeline:
              - pingFn
Outputs:
  ApiRef:
    Value: !Ref Api
  ApiId:
    Value: !GetAtt Api.ApiId
  ApiArn:
    Value: !GetAtt Api.Arn
"""

_PING_FN_JS = (
    "export function request(ctx) { return {}; }\n"
    "export function response(ctx) { return 'pong'; }\n"
)
_PING_RESOLVER_JS = (
    "export function request(ctx) { return {}; }\n"
    "export function response(ctx) { return ctx.prev.result; }\n"
)


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A Serverless::GraphQLApi expands into an AppSync API with its auth, schema, pipeline function
    and resolver; Ref and GetAtt match the listed API, and stack delete removes the API."""
    cf = ctx.client("cloudformation")
    appsync = ctx.client("appsync")
    s3 = ctx.client("s3")
    stack = ctx.unique_name("sim2real-sam-gql-")
    api_name = ctx.unique_name("sim2real-sam-gql-api-")
    bucket = _code_bucket(ctx, s3, "sim2real-sam-gql-code-")

    stack_id, change_set, status = create_stack_via_change_set(
        ctx, cf, stack, _template(_TEMPLATE, api_name, bucket), _CAPS)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack} ended {status!r} (change set {change_set['Status']!r}: "
        f"{change_set.get('StatusReason')!r}): {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)

    listed = [a for a in paginate(appsync, "list_graphql_apis", "graphqlApis") if a["name"] == api_name]
    assert len(listed) == 1, f"expected one listed API named {api_name!r}; got {listed!r}"
    api_id, api_arn = listed[0]["apiId"], listed[0]["arn"]
    got = (outputs["ApiRef"], outputs["ApiId"], outputs["ApiArn"])
    assert got == (api_arn, api_id, api_arn), (
        f"(Ref, GetAtt ApiId, GetAtt Arn) must be the listed {(api_arn, api_id, api_arn)!r}; "
        f"got {got!r}"
    )
    described = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    got = (described["name"], described["authenticationType"])
    assert got == (api_name, "AWS_IAM"), f"expected {(api_name, 'AWS_IAM')!r}; got {got!r}"

    introspection = json.loads(
        appsync.get_introspection_schema(apiId=api_id, format="JSON")["schema"].read())
    types = {t["name"]: t for t in introspection["data"]["__schema"]["types"]}
    query_fields = [(f["name"], f["type"].get("name")) for f in types["Query"]["fields"]]
    assert query_fields == [("ping", "String")], (
        f"the declared Query type must be active; got fields {query_fields!r}"
    )

    functions = paginate(appsync, "list_functions", "functions", apiId=api_id)
    assert len(functions) == 1, f"expected the one declared pipeline function; got {functions!r}"
    function = appsync.get_function(apiId=api_id, functionId=functions[0]["functionId"])[
        "functionConfiguration"]
    got = (function["runtime"], function["code"])
    assert got == (_RUNTIME, _PING_FN_JS), f"expected {(_RUNTIME, _PING_FN_JS)!r}; got {got!r}"
    sources = {d["name"]: d["type"] for d in paginate(appsync, "list_data_sources",
                                                       "dataSources", apiId=api_id)}
    assert sources.get(function["dataSourceName"]) == "NONE", (
        f"the function's data source {function['dataSourceName']!r} must be a NONE source; "
        f"sources are {sources!r}"
    )

    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")["resolver"]
    got = (resolver["kind"], resolver["pipelineConfig"]["functions"], resolver["runtime"],
           resolver["code"])
    want = ("PIPELINE", [function["functionId"]], _RUNTIME, _PING_RESOLVER_JS)
    assert got == want, f"Query.ping resolver: expected {want!r}; got {got!r}"

    delete_stack(cf, stack_id)
    expect_error(lambda: appsync.get_graphql_api(apiId=api_id), *_API_GONE)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for key in ("Versions", "DeleteMarkers")
                for v in paginate(s3, "list_object_versions", key, Bucket=bucket)]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _code_bucket(ctx, s3, prefix: str) -> str:
    """A tagged per-run bucket holding the code the template's CodeUri names; cleanup first."""
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_object(Bucket=bucket, Key="pingFn.js", Body=_PING_FN_JS.encode())
    s3.put_object(Bucket=bucket, Key="pingResolver.js", Body=_PING_RESOLVER_JS.encode())
    return bucket


def _template(template: str, api_name: str, bucket: str) -> str:
    return template.replace("__API_NAME__", api_name).replace("__CODE_BUCKET__", bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
