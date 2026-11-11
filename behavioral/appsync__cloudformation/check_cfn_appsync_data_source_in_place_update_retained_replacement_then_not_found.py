"""cfn-appsync-data-source-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-appsync-data-source-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation"]

#: Real-AWS caps: a stack transition takes seconds to minutes and the cap only stops a hung
#: poll. Every wait is also bounded by ctx.time_left().
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A resolver moved to another data source can take a while to serve on the live endpoint.
_CONVERGE_CAP_S = 180.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: AppSync's refusal of an API, and of a read under it, once the API no longer exists.
_NOT_FOUND = ("NotFoundException", "API not found.")

_SCHEMA = "type Query {\n  echo(msg: String): String\n}\n\nschema {\n  query: Query\n}\n"
#: The NONE data source hands request()'s payload back to response() as ctx.result.
_CODE = (
    "export function request(ctx) {\n  return { payload: ctx.args.msg };\n}\n\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)
_ECHO = "query Echo($m: String) { echo(msg: $m) }"


def _template(api_name: str, source: str, description: str) -> str:
    api_id = {"Fn::GetAtt": ["Api", "ApiId"]}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Api": {
                    "Type": "AWS::AppSync::GraphQLApi",
                    "Properties": {
                        "Name": api_name,
                        "AuthenticationType": "API_KEY",
                        "Tags": _TAGS,
                    },
                },
                "Schema": {
                    "Type": "AWS::AppSync::GraphQLSchema",
                    "Properties": {"ApiId": api_id, "Definition": _SCHEMA},
                },
                "Source": {
                    "Type": "AWS::AppSync::DataSource",
                    # Name is create-only, so changing it replaces the data source.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ApiId": api_id,
                        "Name": source,
                        "Type": "NONE",
                        "Description": description,
                    },
                },
                "Echo": {
                    "Type": "AWS::AppSync::Resolver",
                    "DependsOn": ["Schema"],
                    "Properties": {
                        "ApiId": api_id,
                        "TypeName": "Query",
                        "FieldName": "echo",
                        "DataSourceName": {"Fn::GetAtt": ["Source", "Name"]},
                        "Kind": "UNIT",
                        "Runtime": {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"},
                        "Code": _CODE,
                    },
                },
                "Key": {"Type": "AWS::AppSync::ApiKey", "Properties": {"ApiId": api_id}},
            },
            "Outputs": {
                "ApiId": {"Value": api_id},
                "SourceArn": {"Value": {"Fn::GetAtt": ["Source", "DataSourceArn"]}},
                "GraphQLUrl": {"Value": {"Fn::GetAtt": ["Api", "GraphQLUrl"]}},
                "KeyValue": {"Value": {"Fn::GetAtt": ["Key", "ApiKey"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation NONE data source reads back as templated and serves its resolver's query.

    A Description change keeps it; a Name change under UpdateReplacePolicy Retain keeps the old one
    beside the new one the resolver moves to; after the stack delete the read is NotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html
    """
    secrets: list[str] = []
    try:
        cfn = ctx.client("cloudformation")
        appsync = ctx.client("appsync")
        api_name = ctx.unique_name("sim2real-cfnds-")
        first = ctx.unique_name("sim2real_cfnds_a_").replace("-", "_")
        second = ctx.unique_name("sim2real_cfnds_b_").replace("-", "_")
        stack_name = ctx.unique_name("sim2real-cfnds-stack-")
        ref = {"stack": stack_name, "api": None}

        # The replaced data source is retained; it lives under the stack's API and goes with it.
        ctx.on_cleanup(lambda: _redacted(secrets, _delete_data_source, appsync, ref["api"], first))
        ctx.on_cleanup(lambda: _redacted(secrets, _teardown_stack, cfn, ref))

        # ---- 1. create: CloudFormation's view, AppSync's view, and a query through the source
        ref["stack"] = cfn.create_stack(
            StackName=stack_name, TemplateBody=_template(api_name, first, "one"), Tags=_TAGS
        )["StackId"]
        stack = _settle(ctx, cfn, ref["stack"])
        _expect(cfn, stack, "CREATE_COMPLETE")
        out = _outputs(stack)
        api_id, url, key = out["ApiId"], out["GraphQLUrl"], out["KeyValue"]
        secrets.append(key)
        ref["api"] = api_id
        first_arn = out["SourceArn"]
        _assert_arn(ctx, first_arn, "appsync", f"apis/{api_id}/datasources/{first}")
        assert _physical_ids(cfn, ref["stack"])["Source"] == first_arn, "physical id is the ARN"
        _assert_source(appsync, api_id, first, first_arn, "one")
        _assert_resolver_source(appsync, api_id, first)
        probe = ctx.unique_name("echo-")
        _serves(ctx, url, key, _ECHO, {"m": probe}, {"echo": probe}, "the echo query on the source")

        # ---- 2. in-place: a new Description, the same data source
        seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
        cfn.update_stack(
            StackName=ref["stack"], TemplateBody=_template(api_name, first, "two"), Tags=_TAGS
        )
        _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
        assert _physical_ids(cfn, ref["stack"])["Source"] == first_arn, (
            "an in-place update keeps it"
        )
        _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Source"), first_arn, "Source")
        _assert_source(appsync, api_id, first, first_arn, "two")

        # ---- 3. replacement under UpdateReplacePolicy Retain: a new source, the old one kept
        seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
        cfn.update_stack(
            StackName=ref["stack"], TemplateBody=_template(api_name, second, "two"), Tags=_TAGS
        )
        stack = _settle(ctx, cfn, ref["stack"])
        _expect(cfn, stack, "UPDATE_COMPLETE")
        second_arn = _outputs(stack)["SourceArn"]
        _assert_arn(ctx, second_arn, "appsync", f"apis/{api_id}/datasources/{second}")
        assert _physical_ids(cfn, ref["stack"])["Source"] == second_arn, (
            "the stack tracks the new one"
        )
        events = _events(cfn, ref["stack"])
        _assert_replaced_and_retained(
            _rows(events, seen, "Source"), first_arn, second_arn, "Source"
        )
        echo_arn = f"{first_arn.split(':apis/')[0]}:apis/{api_id}/types/Query/resolvers/echo"
        _assert_in_place(_rows(events, seen, "Echo"), echo_arn, "Echo")
        _assert_source(appsync, api_id, second, second_arn, "two")
        _assert_source(appsync, api_id, first, first_arn, "two")
        _assert_resolver_source(appsync, api_id, second)
        probe = ctx.unique_name("echo-")
        _serves(
            ctx, url, key, _ECHO, {"m": probe}, {"echo": probe}, "the echo query on the new source"
        )

        # ---- 4. delete: the stack's data source goes with its API
        _delete_stack(ctx, cfn, ref["stack"])
        got = _wait_error(
            ctx, lambda: appsync.get_graphql_api(apiId=api_id), _NOT_FOUND[0], f"API {api_id}"
        )
        assert got == _NOT_FOUND, (
            f"GetGraphqlApi after the stack delete: {got!r}, want {_NOT_FOUND!r}"
        )
        got = _error(lambda: appsync.get_data_source(apiId=api_id, name=second))
        assert got == _NOT_FOUND, f"GetDataSource {second} after the delete: {got!r}"
    except Exception as exc:
        clean = _redact(str(exc), secrets)
        if clean == str(exc):
            raise
        raise _redacted_error(exc, clean) from None


#: An AppSync API key: never echoed into a failure message.
_KEY_PATTERN = re.compile(r"da2-[0-9A-Za-z]+")


def _redact(text: str, secrets: list[str]) -> str:
    """*text* with every API key (and every value in *secrets*) replaced by a placeholder."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<api-key>")
    return _KEY_PATTERN.sub("<api-key>", text)


def _redacted(secrets: list[str], fn, *args):
    """Call ``fn(*args)``; an exception whose text holds an API key is re-raised redacted."""
    try:
        return fn(*args)
    except Exception as exc:
        clean = _redact(str(exc), secrets)
        if clean == str(exc):
            raise
        raise _redacted_error(exc, clean) from None


def _redacted_error(exc: Exception, clean: str) -> Exception:
    """*exc* again with the redacted text: a verdict-bearing kind keeps its kind."""
    kind = type(exc) if isinstance(exc, (AssertionError, TimeoutError)) else RuntimeError
    return kind(clean)


def _assert_source(appsync, api_id: str, name: str, arn: str, description: str) -> None:
    """GetDataSource reports the template's NONE data source exactly."""
    source = appsync.get_data_source(apiId=api_id, name=name)["dataSource"]
    got = {k: source.get(k) for k in ("name", "type", "description", "dataSourceArn")}
    want = {"name": name, "type": "NONE", "description": description, "dataSourceArn": arn}
    assert got == want, f"GetDataSource {name}: {got!r}, expected {want!r}"


def _assert_resolver_source(appsync, api_id: str, name: str) -> None:
    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    got = resolver.get("dataSourceName")
    assert got == name, f"the echo resolver must use data source {name!r}, it uses {got!r}"


def _delete_data_source(appsync, api_id: str | None, name: str) -> None:
    """Delete the retained data source; one gone with its API is done."""
    if api_id is None:
        return
    try:
        appsync.delete_data_source(apiId=api_id, name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ctx=None
    and waits the full cap; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits use their fixed caps, not the runner's remaining time (see _budget_s).
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
    _delete_stack(None, cfn, stack["StackId"])


def _poll(ctx, read, done, what: str, cap_s: float = _CONVERGE_CAP_S):
    """Poll ``read()`` until ``done(value)``; return that value (an eventually consistent read)."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}; last {value!r}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last {value!r}")
        time.sleep(_POLL_S)


def _assert_arn(ctx, arn: str, service: str, resource: str) -> None:
    """*arn* names *resource* of *service* in the run's region and account (any partition)."""
    parts = arn.split(":", 5)
    got = (parts[0], parts[2:]) if len(parts) == 6 else (arn, [])
    want = ("arn", [service, ctx.region, ctx.account, resource])
    assert got == want, f"ARN {arn!r} must be arn:<partition>:{':'.join(want[1])}"


def _graphql(ctx, url: str, api_key: str, query: str, variables: dict | None = None):
    """POST one GraphQL request with an API key -> (HTTP status, parsed body).

    A 4xx is a result; a transport failure is (None, its kind), which a poll retries.
    """
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url,
        data=json.dumps({"query": query, "variables": variables or {}}).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "x-api-key": api_key, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        # A new endpoint can reset, time out or not resolve for a moment; the caller polls.
        return None, {"transport": type(exc).__name__}
    try:
        return status, json.loads(raw) if raw else {}
    except ValueError:
        return status, {"raw": raw}


def _serves(ctx, url: str, api_key: str, query: str, variables: dict | None, want: dict, what: str):
    """Poll the live endpoint until *query* answers HTTP 200 with exactly ``{"data": want}``."""
    _poll(
        ctx,
        lambda: _graphql(ctx, url, api_key, query, variables),
        lambda got: got == (200, {"data": want}),
        what,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
