"""cfn-appsync-api-key-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-appsync-api-key-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation"]

#: Real-AWS caps: a stack transition takes seconds to minutes and the cap only stops a hung
#: poll. Every wait is also bounded by ctx.time_left().
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A new API key can take a while to authorize on the live endpoint.
_CONVERGE_CAP_S = 180.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: AppSync's refusal of an API, and of a read under it, once the API no longer exists.
_NOT_FOUND = ("NotFoundException", "API not found.")
#: The live endpoint's answer to an API key that is not one of the API's own.
_FOREIGN_KEY = (
    401,
    {
        "errors": [
            {
                "errorType": "UnauthorizedException",
                "message": "You are not authorized to make this call.",
            }
        ]
    },
)

_SCHEMA = "type Query {\n  ping: String\n}\n\nschema {\n  query: Query\n}\n"
_TYPENAME = "{ __typename }"


def _template(prefix: str, target: str, description: str) -> str:
    resources = {
        # ApiId is create-only, so moving the key to the other API replaces it.
        "Key": {
            "Type": "AWS::AppSync::ApiKey",
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "ApiId": {"Fn::GetAtt": [f"Api{target}", "ApiId"]},
                "Description": description,
            },
        },
    }
    outputs = {
        "KeyArn": {"Value": {"Ref": "Key"}},
        "KeyId": {"Value": {"Fn::GetAtt": ["Key", "ApiKeyId"]}},
        "KeyValue": {"Value": {"Fn::GetAtt": ["Key", "ApiKey"]}},
    }
    for side in ("A", "B"):
        resources[f"Api{side}"] = {
            "Type": "AWS::AppSync::GraphQLApi",
            "Properties": {
                "Name": f"{prefix}{side}",
                "AuthenticationType": "API_KEY",
                "Tags": _TAGS,
            },
        }
        resources[f"Schema{side}"] = {
            "Type": "AWS::AppSync::GraphQLSchema",
            "Properties": {"ApiId": {"Fn::GetAtt": [f"Api{side}", "ApiId"]}, "Definition": _SCHEMA},
        }
        outputs[f"Api{side}"] = {"Value": {"Fn::GetAtt": [f"Api{side}", "ApiId"]}}
        outputs[f"Url{side}"] = {"Value": {"Fn::GetAtt": [f"Api{side}", "GraphQLUrl"]}}
    resources["Key"]["DependsOn"] = ["SchemaA", "SchemaB"]
    return json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs}
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
    """A CloudFormation API key lists as templated and authorizes its own API only (others: 401).

    A Description change keeps the key; an ApiId change under UpdateReplacePolicy Retain keeps the
    old key working beside the new; after the stack delete ListApiKeys is NotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-apikey.html
    """
    secrets: list[str] = []
    try:
        cfn = ctx.client("cloudformation")
        appsync = ctx.client("appsync")
        prefix = ctx.unique_name("sim2real-cfnkey-")
        stack_name = ctx.unique_name("sim2real-cfnkey-stack-")
        ref = {"stack": stack_name, "api": None, "key": None}

        # The replaced key is retained; it lives under the stack's first API and goes with it.
        ctx.on_cleanup(lambda: _redacted(secrets, _delete_key, appsync, ref["api"], ref["key"]))
        ctx.on_cleanup(lambda: _redacted(secrets, _teardown_stack, cfn, ref))

        # ---- 1. create on API A: CloudFormation's view, AppSync's view, the key authorizes A only
        ref["stack"] = cfn.create_stack(
            StackName=stack_name, TemplateBody=_template(prefix, "A", "one"), Tags=_TAGS
        )["StackId"]
        stack = _settle(ctx, cfn, ref["stack"])
        _expect(cfn, stack, "CREATE_COMPLETE")
        out = _outputs(stack)
        api_a, api_b, url_a, url_b = out["ApiA"], out["ApiB"], out["UrlA"], out["UrlB"]
        secrets.extend([out["KeyId"], out["KeyValue"]])
        ref["api"], ref["key"] = api_a, out["KeyId"]
        first_arn, first_key = out["KeyArn"], out["KeyValue"]
        _assert_arn(ctx, first_arn, "appsync", f"apis/{api_a}/apikeys/{out['KeyId']}")
        assert out["KeyId"] == first_key, "ApiKeyId is the key value"
        assert _physical_ids(cfn, ref["stack"])["Key"] == first_arn, "physical id is the key ARN"
        assert _keys(appsync, api_a) == {first_key: "one"}, "ListApiKeys of API A after create"
        assert _keys(appsync, api_b) == {}, "ListApiKeys of API B after create"
        _serves(ctx, url_a, first_key, _TYPENAME, None, {"__typename": "Query"}, "the key on A")
        got = _answered(ctx, url_b, first_key, "API B with API A's key")
        assert got == _FOREIGN_KEY, f"API B with API A's key: {got!r}, want {_FOREIGN_KEY!r}"

        # ---- 2. in-place: a new Description, the same key
        seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
        cfn.update_stack(
            StackName=ref["stack"], TemplateBody=_template(prefix, "A", "two"), Tags=_TAGS
        )
        stack = _settle(ctx, cfn, ref["stack"])
        _expect(cfn, stack, "UPDATE_COMPLETE")
        assert _physical_ids(cfn, ref["stack"])["Key"] == first_arn, "an in-place update keeps it"
        _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Key"), first_arn, "Key")
        assert _outputs(stack)["KeyValue"] == first_key, "an in-place update keeps the key value"
        assert _keys(appsync, api_a) == {first_key: "two"}, "ListApiKeys of API A after the update"
        _serves(ctx, url_a, first_key, _TYPENAME, None, {"__typename": "Query"}, "the updated key")

        # ---- 3. replacement under UpdateReplacePolicy Retain: a key on B, A's key kept
        seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
        cfn.update_stack(
            StackName=ref["stack"], TemplateBody=_template(prefix, "B", "two"), Tags=_TAGS
        )
        stack = _settle(ctx, cfn, ref["stack"])
        _expect(cfn, stack, "UPDATE_COMPLETE")
        out = _outputs(stack)
        second_arn, second_key = out["KeyArn"], out["KeyValue"]
        secrets.append(second_key)
        _assert_arn(ctx, second_arn, "appsync", f"apis/{api_b}/apikeys/{second_key}")
        assert _physical_ids(cfn, ref["stack"])["Key"] == second_arn, "the stack tracks the new key"
        _assert_replaced_and_retained(
            _rows(_events(cfn, ref["stack"]), seen, "Key"), first_arn, second_arn, "Key"
        )
        assert _keys(appsync, api_a) == {first_key: "two"}, "the retained key stays on API A"
        assert _keys(appsync, api_b) == {second_key: "two"}, "the new key is on API B"
        _serves(
            ctx, url_b, second_key, _TYPENAME, None, {"__typename": "Query"}, "the new key on B"
        )
        _serves(
            ctx, url_a, first_key, _TYPENAME, None, {"__typename": "Query"}, "the kept key on A"
        )
        got = _answered(ctx, url_a, second_key, "API A with API B's key")
        assert got == _FOREIGN_KEY, f"API A with API B's key: {got!r}, want {_FOREIGN_KEY!r}"

        # ---- 4. delete: the stack's key goes with its API
        _delete_stack(ctx, cfn, ref["stack"])
        got = _wait_error(ctx, lambda: appsync.list_api_keys(apiId=api_b), _NOT_FOUND[0], "API B")
        assert got == _NOT_FOUND, (
            f"ListApiKeys of API B after the delete: {got!r}, want {_NOT_FOUND!r}"
        )
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


def _answered(ctx, url: str, api_key: str, what: str) -> tuple:
    """The live endpoint's first HTTP answer to ``{ __typename }``, past transport failures."""
    return _poll(
        ctx, lambda: _graphql(ctx, url, api_key, _TYPENAME), lambda got: got[0] is not None, what
    )


def _keys(appsync, api_id: str) -> dict[str, str | None]:
    """Key id -> description of every API key of *api_id*."""
    keys = {}
    for page in appsync.get_paginator("list_api_keys").paginate(apiId=api_id):
        keys.update({k["id"]: k.get("description") for k in page["apiKeys"]})
    return keys


def _delete_key(appsync, api_id: str | None, key_id: str | None) -> None:
    """Delete the retained key; one gone with its API is done."""
    if api_id is None or key_id is None:
        return
    try:
        appsync.delete_api_key(apiId=api_id, id=key_id)
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
