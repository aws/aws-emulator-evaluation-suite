"""cdk-authenticated-graphql-app-workflow."""
from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-authenticated-graphql-app-workflow"
GROUP = "deployment-order"
SERVICES = ["appsync", "cloudwatch", "cognito-idp", "dynamodb", "logs"]

_APP_DIR = Path(__file__).parent / "deployments" / "graphql_app_cdk"

_MUTATION = """
mutation Add($id: ID!, $text: String!) {
  addNote(id: $id, text: $text) { id text owner label }
}
"""

_QUERY = """
query Get($id: ID!) {
  getNote(id: $id) { id text owner label }
}
"""


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A CDK-deployed AppSync + Cognito + DynamoDB app authenticates, persists, refuses bad tokens,
    logs, alarms, denies an unpermitted write, updates in place, and stops writing once deleted.
    """
    alerts = _create_queue(ctx, "alerts", allow_services=("sns.amazonaws.com",))
    base_context = {
        "alerts_queue_arn": alerts["arn"],
        "metric_namespace": _xname(ctx, "ns"),
    }
    happy_context = {
        **base_context,
        "variant": "ok",
        "api_name": _xname(ctx, "api"),
        "pool_name": _xname(ctx, "pool"),
        "client_name": _xname(ctx, "cli"),
        "table_name": _xname(ctx, "tbl"),
        "alarm_name": _xname(ctx, "alarm"),
        "stage_label": "v1",
    }

    legs = _Legs(ctx, total=10)
    stack = legs.hard("deploy", lambda: _deploy(ctx, happy_context))
    identity = legs.hard("identity", lambda: _mint_user(ctx, stack["outputs"]))
    legs.step("wiring", lambda: _assert_authenticated_mutation_persists(ctx, stack, identity))
    legs.step("authz", lambda: _assert_unauthenticated_refused(ctx, stack), requires=("wiring",))
    legs.step("logs", lambda: _assert_structured_log(ctx, stack), requires=("wiring",))
    legs.step("metrics", lambda: _assert_metric_datapoint(ctx, stack, legs), requires=("wiring",))
    legs.step("alarm", lambda: _assert_alarm_notifies(ctx, stack, identity, alerts, legs), requires=("metrics",))
    legs.step("denial", lambda: _assert_unpermitted_resolver_denied(ctx, base_context))
    legs.step("drift", lambda: _assert_second_apply_modifies(ctx, stack, happy_context, identity), requires=("wiring",))
    legs.step("teardown", lambda: _assert_delete_stops_writes(ctx, stack, identity), requires=("wiring",))
    legs.verdict()


# --- legs ---------------------------------------------------------------------------------------
def _deploy(ctx, context: dict[str, str]) -> dict[str, Any]:
    stack = _deploy_cdk(ctx, _APP_DIR, context=context)
    outputs = stack["outputs"]
    for key in (
        "ApiId", "GraphQLUrl", "UserPoolId", "UserPoolClientId", "TableName", "LogGroupName",
        "AlarmName", "MetricNamespace",
    ):
        assert outputs.get(key), f"stack output {key} is absent: {sorted(outputs)}"
    return stack


def _assert_authenticated_mutation_persists(ctx, stack, identity) -> str:
    """The authorizer admits the token, the VTL stamps the identity into the item, and the item
    reads back through both the GraphQL resolver and the DynamoDB API."""
    out = stack["outputs"]
    note_id = ctx.unique_name("note-")
    status, doc = _graphql(ctx, out["GraphQLUrl"], identity["token"], _MUTATION, {"id": note_id, "text": "hello"})
    assert status == 200, f"the authenticated mutation answered {status}: {_one_line(doc, 200)}"
    assert not doc.get("errors"), f"the mutation reported errors: {_one_line(doc.get('errors'), 300)}"
    note = (doc.get("data") or {}).get("addNote") or {}
    assert note.get("id") == note_id, doc
    assert note.get("text") == "hello", doc
    assert note.get("owner") == identity["username"], (
        f"the resolver must stamp the ADMITTED identity, got owner={note.get('owner')!r} for "
        f"{identity['username']!r}"
    )
    assert note.get("label") == out["StageLabel"], doc

    status, doc = _graphql(ctx, out["GraphQLUrl"], identity["token"], _QUERY, {"id": note_id})
    assert status == 200 and not doc.get("errors"), _one_line(doc, 300)
    assert (doc.get("data") or {}).get("getNote", {}).get("text") == "hello", doc

    item = _ddb_item(ctx, out["TableName"], note_id)
    assert item is not None, f"{out['TableName']} does not hold {note_id} the resolver reported writing"
    assert item["owner"]["S"] == identity["username"], item
    assert item["label"]["S"] == out["StageLabel"], item
    return f"{note_id} written as owner={identity['username'][:28]}, readable both ways"


def _assert_unauthenticated_refused(ctx, stack) -> str:
    """Requests with no token and with a malformed token are both refused with
    UnauthorizedException, and neither leaves an item behind."""
    out = stack["outputs"]
    note_id = ctx.unique_name("unauth-note-")
    outcomes = []
    # The authorizer's exact message differs by how the request failed: no token to evaluate at
    # all, versus a token present but not a parseable JWT.
    cases = (
        ("absent header", None, "You are not authorized to make this call."),
        ("malformed token", "Bearer not-a-real-id-token", "Unable to parse JWT token."),
    )
    for label, token, want_message in cases:
        status, doc = _graphql(ctx, out["GraphQLUrl"], token, _MUTATION, {"id": note_id, "text": "nope"})
        errors = json.dumps(doc.get("errors") or doc)
        assert status == 401, f"{label}: expected 401 from the authorizer, got {status}: {errors[:200]}"
        assert doc.get("errors") == [{"errorType": "UnauthorizedException", "message": want_message}], (
            f"{label}: the authorizer refusal must be exactly one UnauthorizedException with "
            f"message {want_message!r}, got {errors[:300]}"
        )
        outcomes.append(f"{label}=401")
    assert _ddb_item(ctx, out["TableName"], note_id) is None, (
        f"{out['TableName']} holds {note_id} although every attempt was refused by the authorizer"
    )
    return f"{', '.join(outcomes)}, table holds no refused note"


def _assert_structured_log(ctx, stack) -> str:
    """AppSync writes its request entries into the log group the stack declared."""
    out = stack["outputs"]
    log_group = out["LogGroupName"]
    message = _await_log_line(ctx, log_group, (out["ApiId"], "logType"), timeout_s=300)
    streams = _log_group_streams(ctx, log_group)
    assert streams, f"{log_group} carried the entry but reports no stream"
    return f"{log_group} stream {streams[0][:40]} carries {_one_line(message, 40)}"


def _assert_metric_datapoint(ctx, stack, legs) -> str:
    """The metric filter over the request log group produces a datapoint (no PutMetricData)."""
    return _await_metric(
        ctx, stack["outputs"]["MetricNamespace"], "GraphQLRequests", [], timeout_s=480, legs=legs
    )


def _assert_alarm_notifies(ctx, stack, identity, alerts, legs) -> str:
    out = stack["outputs"]
    alarm = out["AlarmName"]
    counter = {"n": 0}

    def _feed() -> None:
        counter["n"] += 1
        _graphql(ctx, out["GraphQLUrl"], identity["token"], _QUERY, {"id": f"alarm-{counter['n']}"})

    transitions = _await_alarm_state(ctx, alarm, "ALARM", timeout_s=540, legs=legs, feed=_feed)
    payload = _await_report(
        ctx,
        alerts["url"],
        lambda d: d.get("AlarmName") == alarm and d.get("NewStateValue") == "ALARM",
        timeout_s=300,
        description=f"alarm notification for {alarm}",
    )
    assert payload["OldStateValue"] == "INSUFFICIENT_DATA", (
        f"a never-fed alarm starts INSUFFICIENT_DATA, so the graded transition must report "
        f"OldStateValue=INSUFFICIENT_DATA, got {payload.get('OldStateValue')!r}"
    )
    trigger = payload.get("Trigger") or {}
    assert trigger.get("MetricName") == "GraphQLRequests", trigger
    return f"{transitions}; notified with Trigger on {out['MetricNamespace']}"


def _assert_unpermitted_resolver_denied(ctx, base_context: dict[str, str]) -> str:
    """With dynamodb:PutItem removed from the data source role, the mutation returns a resolver
    error in an HTTP 200 and writes nothing, while the Query resolver on that role still serves.

    AppSync reports the IAM refusal as errorType DynamoDB:DynamoDbException; it only reaches the
    response because the mapping template calls $util.error on $ctx.error.
    """
    broken = _deploy_cdk(
        ctx,
        _APP_DIR,
        context={
            **base_context,
            "variant": "deny_putitem",
            "api_name": _xname(ctx, "api"),
            "pool_name": _xname(ctx, "pool"),
            "client_name": _xname(ctx, "cli"),
            "table_name": _xname(ctx, "tbl"),
            "alarm_name": _xname(ctx, "alarm"),
            "stage_label": "denied",
        },
    )
    try:
        out = broken["outputs"]
        identity = _mint_user(ctx, out)
        seeded = ctx.unique_name("seeded-note-")
        ctx.client("dynamodb").put_item(
            TableName=out["TableName"],
            Item={
                "id": {"S": seeded},
                "text": {"S": "seeded"},
                "owner": {"S": "seed"},
                "label": {"S": "denied"},
            },
        )
        status, doc = _graphql(ctx, out["GraphQLUrl"], identity["token"], _QUERY, {"id": seeded})
        assert status == 200 and not doc.get("errors"), (
            f"control: the read path must still serve, got {status}: {_one_line(doc, 200)}"
        )
        assert (doc.get("data") or {}).get("getNote", {}).get("text") == "seeded", doc

        note_id = ctx.unique_name("denied-note-")
        status, doc = _graphql(
            ctx, out["GraphQLUrl"], identity["token"], _MUTATION, {"id": note_id, "text": "nope"}
        )
        assert status == 200, (
            f"a resolver failure is GraphQL 200 with an errors entry, not a transport status; "
            f"got {status}: {_one_line(doc, 200)}"
        )
        errors = json.dumps(doc.get("errors") or [])
        assert doc.get("errors"), f"the refused mutation reported no error: {_one_line(doc, 300)}"
        assert (doc.get("data") or {}).get("addNote") is None, doc
        error0 = (doc.get("errors") or [{}])[0]
        assert error0.get("errorType") == "DynamoDB:DynamoDbException", (
            f"an IAM-denied direct DynamoDB resolver call surfaces as errorType "
            f"DynamoDB:DynamoDbException (there is no distinct AccessDenied errorType), got "
            f"{error0.get('errorType')!r}: {errors[:400]}"
        )
        assert "not authorized to perform" in errors, (
            f"the denial must name the refusal: {errors[:400]}"
        )
        assert "PutItem" in errors, f"the denial must name the refused action: {errors[:400]}"
        assert _ddb_item(ctx, out["TableName"], note_id) is None, (
            f"{out['TableName']} holds {note_id} although the resolver was refused PutItem"
        )
        return f"read path serves, mutation refused DynamoDB:DynamoDbException on PutItem, {note_id} absent"
    finally:
        # Deleted in-band rather than left to ctx.run_cleanups: the cleanup budget is far below a
        # CloudFormation delete, so a failing assertion here would otherwise strand the stack.
        _delete_stack_and_wait(ctx, broken["stack_name"])


def _assert_second_apply_modifies(ctx, stack, happy_context: dict[str, str], identity) -> str:
    """A second apply changing the mapping template keeps every physical resource id and the new
    template serves requests."""
    name = stack["stack_name"]
    before = _stack_resources(ctx, name)
    outputs = _update_cdk_stack(
        ctx, name, _APP_DIR, context={**happy_context, "stage_label": "v2"}
    )
    after = _stack_resources(ctx, name)
    replaced = []
    for resource_type in (
        "AWS::AppSync::GraphQLApi",
        "AWS::AppSync::Resolver",
        "AWS::Cognito::UserPool",
        "AWS::DynamoDB::Table",
    ):
        was = _physical_ids_of_type(before, resource_type)
        now = _physical_ids_of_type(after, resource_type)
        assert was, f"{resource_type} had no physical id before the second apply"
        if was != now:
            replaced.append(f"{resource_type}: {was} -> {now}")
    assert not replaced, f"the second apply REPLACED resources it should have modified: {replaced}"
    assert outputs["StageLabel"] == "v2", outputs

    note_id = ctx.unique_name("drift-note-")
    status, doc = _graphql(
        ctx, outputs["GraphQLUrl"], identity["token"], _MUTATION, {"id": note_id, "text": "after"}
    )
    assert status == 200 and not doc.get("errors"), _one_line(doc, 300)
    note = (doc.get("data") or {}).get("addNote") or {}
    assert note.get("label") == "v2", f"the old mapping template is still serving: {doc}"
    item = _ddb_item(ctx, outputs["TableName"], note_id)
    assert item is not None and item["label"]["S"] == "v2", item
    return "api/resolver/pool/table modified not replaced, the v2 template serves"


def _assert_delete_stops_writes(ctx, stack, identity) -> str:
    """After the delete the API, user pool and table are gone and the mutation no longer writes.

    The log group is named after the API id, so CloudFormation deletes it before the Api and AppSync
    recreates it empty while the Api tears down; that remnant is asserted empty and deleted here.
    """
    out = _stack_outputs(ctx, stack["stack_name"])
    _delete_stack_and_wait(ctx, stack["stack_name"])

    assert _stack_status(ctx, stack["stack_name"]) in {"DELETE_COMPLETE", "GONE"}, (
        f"stack still reports {_stack_status(ctx, stack['stack_name'])}"
    )

    survivors = [
        label
        for label, present in (
            (f"api {out['ApiId']}", _graphql_api_exists(ctx, out["ApiId"])),
            (f"user pool {out['UserPoolId']}", _user_pool_exists(ctx, out["UserPoolId"])),
            (f"table {out['TableName']}", _table_exists(ctx, out["TableName"])),
        )
        if present
    ]
    assert not survivors, f"these survived the stack delete: {survivors}"

    if _log_group_exists(ctx, out["LogGroupName"]):
        detail = ctx.client("logs").describe_log_groups(
            logGroupNamePrefix=out["LogGroupName"]
        )["logGroups"][0]
        # storedBytes is the invariant, not stream count: AppSync's recreation opens an empty
        # stream shell with nothing ever flushed into it.
        assert detail.get("storedBytes", 0) == 0, (
            f"{out['LogGroupName']} survived the delete AND holds data -- not the empty "
            f"teardown-race artifact: {detail}"
        )
        ctx.client("logs").delete_log_group(logGroupName=out["LogGroupName"])

    status, doc = _graphql(
        ctx,
        out["GraphQLUrl"],
        identity["token"],
        _MUTATION,
        {"id": ctx.unique_name("post-delete-note-"), "text": "nope"},
    )
    refused = status != 200 or bool(doc.get("errors"))
    assert refused, f"the deleted API still accepted the mutation: {status} {_one_line(doc, 200)}"
    return f"api/pool/table gone, any log-group teardown-race remnant was empty, mutation answers {status}"


# --- probes -------------------------------------------------------------------------------------
def _mint_user(ctx, outputs: dict[str, str]) -> dict[str, str]:
    """Create a confirmed user in the deployed pool; return an id token via USER_PASSWORD_AUTH."""
    idp = ctx.client("cognito-idp")
    pool_id = outputs["UserPoolId"]
    username = ctx.unique_name("user-")
    password = "Aa1!" + ctx.unique_name("pw-")[:24]
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = idp.initiate_auth(
        ClientId=outputs["UserPoolClientId"],
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    result = auth.get("AuthenticationResult") or {}
    assert result.get("IdToken"), f"USER_PASSWORD_AUTH returned no id token: {_one_line(auth, 200)}"
    return {"username": username, "token": result["IdToken"]}


def _graphql(ctx, url: str, token: str | None, query: str, variables: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """One GraphQL POST; a transport-level failure returns status 0."""
    route_url, route_headers = ctx.endpoint_route(url)
    headers = {"Content-Type": "application/json", **route_headers}
    if token:
        headers["Authorization"] = token
    req = urllib.request.Request(
        route_url,
        data=json.dumps({"query": query, "variables": variables}).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status, _json_or_raw(resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, _json_or_raw(exc.read().decode(errors="replace"))
    except urllib.error.URLError as exc:
        return 0, {"transport": _one_line(exc)}


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _json_or_raw(text: str) -> dict[str, Any]:
    try:
        doc = json.loads(text or "{}")
    except (json.JSONDecodeError, ValueError):
        return {"raw": text[:400]}
    return doc if isinstance(doc, dict) else {"raw": text[:400]}


def _ddb_item(ctx, table: str, note_id: str) -> dict[str, Any] | None:
    try:
        return ctx.client("dynamodb").get_item(
            TableName=table, Key={"id": {"S": note_id}}, ConsistentRead=True
        ).get("Item")
    except ClientError:
        return None


def _graphql_api_exists(ctx, api_id: str) -> bool:
    try:
        ctx.client("appsync").get_graphql_api(apiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"NotFoundException", "ResourceNotFoundException"}:
            return False
        raise
    return True


def _user_pool_exists(ctx, pool_id: str) -> bool:
    try:
        ctx.client("cognito-idp").describe_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"ResourceNotFoundException", "NotFoundException"}:
            return False
        raise
    return True


def _table_exists(ctx, table: str) -> bool:
    try:
        ctx.client("dynamodb").describe_table(TableName=table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"ResourceNotFoundException", "NotFoundException"}:
            return False
        raise
    return True


def _log_group_exists(ctx, log_group: str) -> bool:
    groups = ctx.client("logs").describe_log_groups(logGroupNamePrefix=log_group).get(
        "logGroups", []
    )
    return any(g["logGroupName"] == log_group for g in groups)


_EVIDENCE_CAP = 120
_HEADLINE_CAP = 280


def _one_line(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Collapse to a single line so evidence cannot displace the summary as the last line."""
    flat = " ".join(str(text).split())
    return flat[:cap]


class _Legs:
    """One PASS / FAIL / BLOCKED verdict per workflow leg, raised once at the end with the summary
    as the last line of the message."""

    def __init__(self, ctx, total: int) -> None:
        self._ctx = ctx
        self._total = total
        self._rows: list[tuple[str, str, str]] = []
        self._failed: set[str] = set()
        # Failed OR blocked: gating on failures alone would run a leg against state a blocked
        # prerequisite never produced.
        self._not_passed: set[str] = set()

    def _record(self, name: str, verdict: str, evidence: str) -> None:
        self._rows.append((name, verdict, evidence))
        # Printed as it happens so a run killed mid-way still shows which legs it proved.
        print(f"[leg {len(self._rows)}/{self._total}] {verdict:7} {name}: {evidence}", flush=True)

    def step(self, name: str, fn, *, requires: tuple[str, ...] = ()):
        """Run leg *name*; record BLOCKED when a prerequisite did not pass, so one broken hop is not
        reported as a failure per downstream leg."""
        blocked_by = [r for r in requires if r in self._not_passed]
        if blocked_by:
            self._not_passed.add(name)
            self._record(name, "BLOCKED", f"requires {','.join(blocked_by)}")
            return None
        try:
            evidence = fn()
        except AssertionError:
            raise
        except BaseException as exc:  # noqa: BLE001 -- recorded, then re-raised in aggregate
            self._failed.add(name)
            self._not_passed.add(name)
            self._record(name, "FAIL", _one_line(exc))
            return None
        self._record(name, "PASS", _one_line(evidence if evidence is not None else "ok"))
        return evidence

    def hard(self, name: str, fn):
        """Run a prerequisite leg (deploy, bootstrap) and raise immediately if it fails."""
        try:
            evidence = fn()
        except AssertionError:
            raise
        except BaseException as exc:  # noqa: BLE001
            self._record(name, "FAIL", _one_line(exc))
            raise AssertionError(self._summary(name, _one_line(exc))) from exc
        self._record(name, "PASS", _one_line(evidence if evidence is not None else "ok"))
        return evidence

    def never_reached(self, what: str, waited_s: float):
        """Fail for a state the target accepted and never reached."""
        raise AssertionError(f"{what}; not reached after {waited_s:.0f}s of polling")

    def _summary(self, headline_leg: str, headline_evidence: str) -> str:
        n_pass = sum(1 for _, v, _ in self._rows if v == "PASS")
        cells = " ".join(f"{n}={v}" for n, v, _ in self._rows)
        # Truncate the cells, never the headline: the headline is the line that survives.
        head = _one_line(f"WORKFLOW FAILED at {headline_leg}: {headline_evidence}", _HEADLINE_CAP)
        return f"LEGS {n_pass}/{self._total} PASS | {cells[:900]}\n{head}"

    def verdict(self) -> None:
        """Raise once if any leg failed. Call as the LAST statement of run()."""
        n_pass = sum(1 for _, v, _ in self._rows if v == "PASS")
        print(f"[legs] {n_pass}/{self._total} PASS", flush=True)
        if not self._failed:
            return
        leg, _, evidence = next(r for r in self._rows if r[1] == "FAIL")
        raise AssertionError(self._summary(leg, evidence))


# --- naming + tagging: cleanup matches on this prefix.
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"
_CDK_BOOTSTRAP_PARAM = "BootstrapVersion"
_CDK_BOOTSTRAP_RULE = "CheckBootstrapVersion"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


# --- CloudFormation ----------------------------------------------------------------------------
def _stack_status(ctx, stack_name: str) -> str:
    cfn = ctx.client("cloudformation")
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _stack_outputs(ctx, stack_name: str) -> dict[str, str]:
    stack = ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _stack_failure_reasons(ctx, stack_name: str, limit: int = 3) -> str:
    """The FAILED stack events' reasons on one line; a rollback status alone names no cause."""
    try:
        events = ctx.client("cloudformation").describe_stack_events(StackName=stack_name)[
            "StackEvents"
        ]
    except ClientError as exc:
        return f"<events unavailable: {exc}>"
    reasons = [
        f"{e.get('LogicalResourceId')}={e.get('ResourceStatusReason')}"
        for e in events
        if str(e.get("ResourceStatus", "")).endswith("_FAILED") and e.get("ResourceStatusReason")
    ]
    return _one_line("; ".join(reasons[:limit]) or "<no FAILED event carried a reason>", 400)


def _stack_resources(ctx, stack_name: str) -> list[dict[str, str]]:
    """Every resource in the stack with its type and physical id; an unchanged physical id across
    applies means modified in place. Selected by type because CDK hashes logical ids."""
    cfn = ctx.client("cloudformation")
    out: list[dict[str, str]] = []
    token: str | None = None
    while True:
        kwargs = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.list_stack_resources(**kwargs)
        for res in page.get("StackResourceSummaries", []):
            out.append(
                {
                    "logical": res.get("LogicalResourceId", ""),
                    "physical": res.get("PhysicalResourceId", ""),
                    "type": res.get("ResourceType", ""),
                }
            )
        token = page.get("NextToken")
        if not token:
            return out


def _physical_ids_of_type(resources: list[dict[str, str]], resource_type: str) -> list[str]:
    return sorted(r["physical"] for r in resources if r["type"] == resource_type and r["physical"])


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=900.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )
    status = _stack_status(ctx, stack_name)
    if status == "DELETE_FAILED":
        raise RuntimeError(
            f"stack {stack_name} ended DELETE_FAILED: {_stack_failure_reasons(ctx, stack_name)}"
        )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=900.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: _stack_status(ctx, name),
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    status = _stack_status(ctx, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(
            f"stack {name} ended in {status}: {_stack_failure_reasons(ctx, name)}"
        )
    return {"stack_name": name, "stack_id": stack_id, "outputs": _stack_outputs(ctx, name)}


# --- CDK, asset-free --------------------------------------------------------------------------
def _strip_cdk_bootstrap(template_json: str) -> str:
    doc = json.loads(template_json)
    params = doc.get("Parameters") or {}
    rules = doc.get("Rules") or {}
    params.pop(_CDK_BOOTSTRAP_PARAM, None)
    rules.pop(_CDK_BOOTSTRAP_RULE, None)
    for key, value in (("Parameters", params), ("Rules", rules)):
        if value:
            doc[key] = value
        else:
            doc.pop(key, None)
    rest = json.dumps(doc)
    for marker in ("/cdk-bootstrap/", "cdk-hnb659fds-assets"):
        if marker in rest:
            raise AssertionError(
                f"CDK app needs a bootstrapped environment ({marker} referenced) — it has file or "
                "image assets. Make the app asset-free (inline Lambda code as a string) so the "
                "synthesized template deploys through plain CloudFormation."
            )
    return rest


def _synth_cdk_template(ctx, app_dir, *, stack=None, context=None) -> str:
    """`cdk synth` the app into a bootstrap-free CloudFormation body."""
    require_tools("cdk")
    ctx.verify_account_safety()

    src = Path(app_dir)
    work = Path(tempfile.mkdtemp(prefix="sim2real-xsvc-cdk-"))
    shutil.copytree(
        src,
        work,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("cdk.out", ".venv", "__pycache__", "node_modules"),
    )
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))

    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = _account_id(ctx)

    asm = work / "cdk.out"
    cmd = [
        "cdk", "synth",
        "--output", str(asm),
        "--ci",
        "--no-version-reporting",
        "--no-asset-metadata",
        "--no-path-metadata",
    ]
    if stack:
        cmd.append(stack)
    for k, v in (context or {}).items():
        cmd.extend(["--context", f"{k}={v}"])
    synth = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=300)
    if synth.returncode != 0:
        raise AssertionError(f"cdk synth failed: {synth.stderr[-500:]}")

    templates = sorted(asm.glob("*.template.json"))
    if stack:
        templates = [t for t in templates if t.name == f"{stack}.template.json"] or templates
    if not templates:
        raise AssertionError(f"cdk synth produced no template in {asm}")
    if len(templates) > 1:
        names = ", ".join(t.name[: -len(".template.json")] for t in templates)
        raise AssertionError(f"app synthesized {len(templates)} stacks ({names}) — pass stack=...")
    return _strip_cdk_bootstrap(templates[0].read_text())


def _deploy_cdk(ctx, app_dir, *, stack=None, context=None, timeout_s=900.0) -> dict[str, Any]:
    return _deploy_cfn(ctx, _synth_cdk_template(ctx, app_dir, stack=stack, context=context), timeout_s=timeout_s)


def _update_cdk_stack(ctx, stack_name, app_dir, *, stack=None, context=None, timeout_s=900.0) -> dict[str, str]:
    """The SECOND apply: re-synth under changed context and UPDATE the existing stack in place."""
    cfn = ctx.client("cloudformation")
    body = _synth_cdk_template(ctx, app_dir, stack=stack, context=context)
    try:
        cfn.update_stack(
            StackName=stack_name,
            TemplateBody=body,
            Tags=_xsvc_tags_kv(),
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        )
    except ClientError as exc:
        if "No updates are to be performed" in str(exc):
            raise AssertionError(
                "the second apply produced no change set, so nothing about modify-vs-replace was "
                "exercised: the changed context never reached the synthesized template"
            ) from exc
        raise
    # Terminal UPDATE states only. Waiting on a generic "_COMPLETE" would match the CREATE_COMPLETE
    # the stack still carries in the seconds before the update is picked up.
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s
        in {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"update of stack {stack_name}",
    )
    status = _stack_status(ctx, stack_name)
    if status != "UPDATE_COMPLETE":
        raise AssertionError(
            f"second apply of {stack_name} ended in {status}: {_stack_failure_reasons(ctx, stack_name)}"
        )
    return _stack_outputs(ctx, stack_name)


# --- SQS observation channels ------------------------------------------------------------------
def _create_queue(ctx, kind: str = "sink", *, allow_services: tuple[str, ...] = ()) -> dict[str, str]:
    """An SQS queue outside the stack, so it can witness that delivery stopped after the delete."""
    sqs = ctx.client("sqs")
    name = _xname(ctx, kind)
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    if allow_services:
        account = _account_id(ctx)
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": f"allow{svc.split('.')[0]}",
                    "Effect": "Allow",
                    "Principal": {"Service": svc},
                    "Action": "sqs:SendMessage",
                    "Resource": arn,
                    # Scoped to this account rather than to a topic/rule ARN: the sender is created
                    # by the stack that has not been synthesized yet, so its ARN is not knowable
                    # here. aws:SourceAccount still keeps a confused-deputy out.
                    "Condition": {"StringEquals": {"aws:SourceAccount": account}},
                }
                for svc in allow_services
            ],
        }
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"name": name, "url": url, "arn": arn}


def _drain(ctx, queue_url: str) -> None:
    """Discard whatever is already queued so a later absence assertion covers only its window."""
    sqs = ctx.client("sqs")
    for _ in range(10):
        msgs = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not msgs:
            return
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _receive_bodies(ctx, queue_url: str, *, timeout_s: float, predicate=None) -> list[str]:
    """Every body seen in the window, returning early once predicate matches one of them."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            seen.append(msg.get("Body", ""))
        if predicate and any(predicate(b) for b in seen):
            return seen
    return seen


def _unwrap_sns(body: str) -> dict[str, Any] | None:
    """One SQS body -> the JSON an SNS notification carried, or the body's own JSON."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    if doc.get("Type") == "Notification":
        try:
            inner = json.loads(doc["Message"])
        except (KeyError, json.JSONDecodeError, ValueError, TypeError):
            return None
        return inner if isinstance(inner, dict) else None
    return doc


def _await_report(ctx, queue_url: str, predicate, *, timeout_s: float, description: str) -> dict[str, Any]:
    """Poll the sink until a report satisfying predicate arrives; AssertionError names what came."""
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body in _receive_bodies(ctx, queue_url, timeout_s=10.0):
            doc = _unwrap_sns(body)
            if doc is None:
                continue
            seen.append(doc)
            if predicate(doc):
                return doc
    raise AssertionError(
        f"{description} never arrived in {timeout_s:.0f}s of polling. "
        f"Reports seen: {_one_line(json.dumps(seen)[:400], 400)}"
    )


# --- observability probes ----------------------------------------------------------------------
def _await_log_line(ctx, log_group: str, needles: tuple[str, ...], *, timeout_s: float) -> str:
    """The first log event in *log_group* containing every needle (FilterLogEvents: the stream
    name is chosen by the service)."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    seen = 0
    while time.monotonic() < deadline:
        try:
            events = logs.filter_log_events(logGroupName=log_group, limit=200).get("events", [])
        except ClientError:
            events = []  # the group is created by the first invocation; absence means "not yet"
        seen = max(seen, len(events))
        for event in events:
            message = event.get("message", "")
            if all(n in message for n in needles):
                return message
        time.sleep(5.0)
    raise AssertionError(
        f"no line in {log_group} carried all of {needles} within {timeout_s:.0f}s of polling "
        f"({seen} events seen)"
    )


def _log_group_streams(ctx, log_group: str) -> list[str]:
    return [
        s["logStreamName"]
        for s in ctx.client("logs").describe_log_streams(logGroupName=log_group).get("logStreams", [])
    ]


def _metric_sum(ctx, namespace: str, metric: str, dimensions: list[dict[str, str]]) -> float:
    now = datetime.now(timezone.utc)
    points = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=dimensions,
        StartTime=now - timedelta(minutes=20),
        EndTime=now + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )["Datapoints"]
    return sum(float(p["Sum"]) for p in points)


def _await_metric(
    ctx, namespace: str, metric: str, dimensions: list[dict[str, str]], *, timeout_s: float, legs
) -> str:
    """A custom metric datapoint the deployed app published; non-convergence goes to
    legs.never_reached."""
    started = time.monotonic()
    while time.monotonic() - started < timeout_s:
        total = _metric_sum(ctx, namespace, metric, dimensions)
        if total > 0:
            return f"{namespace}/{metric} Sum={total}"
        time.sleep(15.0)
    legs.never_reached(
        f"no {namespace}/{metric} datapoint for {dimensions} after the app published one",
        time.monotonic() - started,
    )
    return ""  # unreachable: never_reached always raises


def _await_alarm_state(ctx, alarm: str, want: str, *, timeout_s: float, legs, feed=None) -> str:
    """Drive the alarm to *want* and return its StateReason; `feed` runs every poll so each
    evaluation cycle sees fresh data."""
    cw = ctx.client("cloudwatch")
    started = time.monotonic()
    states: list[str] = []
    while time.monotonic() - started < timeout_s:
        if feed is not None:
            feed()
        described = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"]
        if described:
            state = described[0]["StateValue"]
            if not states or states[-1] != state:
                states.append(state)
            if state == want:
                return f"{'->'.join(states)} reason={_one_line(described[0].get('StateReason', ''), 60)}"
        time.sleep(15.0)
    legs.never_reached(
        f"alarm {alarm} stayed at {'->'.join(states) or '<absent>'} instead of {want}",
        time.monotonic() - started,
    )
    return ""  # unreachable: never_reached always raises


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
