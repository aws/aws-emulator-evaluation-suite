"""xflavor-order-service-sam."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xflavor-order-service-sam"
GROUP = "deployment-order"
SERVICES = ["apigateway", "cloudwatch", "dynamodb", "lambda", "logs", "sqs"]

_MODULE = Path(__file__).parent / "deployments" / "order_service_sam.yaml"
#: Named in the deploy leg's evidence.
_FLAVOR = "sam"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:eventing", "concern:metrics",
      "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An order-intake app deployed from a SAM template (Serverless transform) serves POST /orders
    end to end via the queue worker, emits logs, metrics and an alarm transition, updates in place
    on a second apply, and is fully gone after the stack is deleted.
    """
    ctx.verify_account_safety()
    legs = _Legs(ctx, total=8)
    state = _new_state(ctx)
    # `requires` names the transitive prerequisite set, so a leg never runs on state a blocked
    # leg never wrote.
    legs.hard("deploy", lambda: _deployed(ctx, state, legs))
    legs.step("wiring", lambda: _assert_order_persisted(ctx, state, legs))
    legs.step("worker", lambda: _assert_order_fulfilled(ctx, state, legs), requires=("wiring",))
    legs.step(
        "logs", lambda: _assert_structured_logs(ctx, state, legs), requires=("wiring", "worker")
    )
    legs.step(
        "metrics", lambda: _assert_metric_datapoint(ctx, state, legs), requires=("wiring", "worker")
    )
    legs.step(
        "alarm",
        lambda: _assert_alarm_transition(ctx, state, legs),
        requires=("wiring", "worker", "metrics"),
    )
    legs.step(
        "drift",
        lambda: _assert_second_apply_modifies_in_place(ctx, state, legs),
        requires=("wiring",),
    )
    # No `requires`: teardown is independently gradeable, and runs in band because a stack delete
    # outlasts the cleanup phase's time bound.
    legs.step("teardown", lambda: _assert_destroy_stops_delivery(ctx, state, legs))
    legs.verdict()


# ===== flavor-specific deploy path =====
# `_apply` and `_destroy` are the two seams the shared legs call; the rest matches the other
# flavors of this application.
# create_stack refuses a template carrying a macro-backed transform without CAPABILITY_AUTO_EXPAND.
_CAPABILITIES = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"]


def _apply(ctx, state, params) -> dict[str, str]:
    """Deploy order_service_sam.yaml: the first call creates the stack, the second updates it, so
    the drift leg exercises a transform re-expansion over a live stack."""
    template = _MODULE.read_text()
    if state.get("stack_name"):
        return _update_cfn(ctx, state, template, parameters=params, timeout_s=_DEPLOY_BUDGET_S)
    return _deploy_cfn(ctx, state, template, parameters=params, timeout_s=_DEPLOY_BUDGET_S)


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _stack_failure_reason(ctx, name: str) -> str:
    """The first resource-level failure reason on the stack; the status alone names no cause."""
    try:
        events = ctx.client("cloudformation").describe_stack_events(StackName=name)["StackEvents"]
    except ClientError as exc:
        return f"(stack events unreadable: {exc})"
    for event in reversed(events):
        if event.get("ResourceStatus", "").endswith("_FAILED") and event.get(
            "ResourceStatusReason"
        ):
            return f"{event.get('LogicalResourceId')}: {event['ResourceStatusReason']}"
    return "(no resource-level failure reason recorded)"


def _wait_stack(ctx, name: str, ok: set[str], timeout_s: float) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in _TERMINAL_STACK_STATUSES,
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"CFN stack {name} reaching a terminal status",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] not in ok:
        raise AssertionError(
            f"stack {name} ended in {stack['StackStatus']}: {_stack_failure_reason(ctx, name)}"
        )
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _deploy_cfn(ctx, state, template, *, timeout_s, parameters=None):
    """create_stack and wait; the stack name lives in *state* so the in-band teardown leg and the
    registered cleanup do not both delete it."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": _CAPABILITIES,
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": str(v)} for k, v in parameters.items()
        ]
    state["StackId"] = cfn.create_stack(**kwargs)["StackId"]
    state["stack_name"] = name
    ctx.on_cleanup(lambda: _destroy(ctx, state, raise_on_leak=True))
    return _wait_stack(ctx, name, {"CREATE_COMPLETE"}, timeout_s)


def _update_cfn(ctx, state, template, *, timeout_s, parameters=None):
    """The second apply, via update_stack so the drift leg grades the real outcome, not a change
    set's prediction."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = state["stack_name"]
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
        "Capabilities": _CAPABILITIES,
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": str(v)} for k, v in parameters.items()
        ]
    cfn.update_stack(**kwargs)
    return _wait_stack(ctx, name, {"UPDATE_COMPLETE"}, timeout_s)


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """delete_stack and wait up to the deploy budget; this stack takes well over two minutes."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status() -> str:
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError:
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=_DEPLOY_BUDGET_S,
        interval_s=10.0,
        description=f"delete stack {stack_name}",
    )


def _destroy(ctx, state, *, raise_on_leak: bool = False) -> str:
    """Delete the stack once, idempotently. In band a failed delete is returned and recorded, as
    the teardown leg grades the resources; with ``raise_on_leak=True`` (cleanup) it raises."""
    name = state.get("stack_name")
    if not name:
        return "no stack was created"
    if state.get("destroyed"):
        if raise_on_leak and state.get("leak"):
            raise RuntimeError(state["leak"])
        return f"stack {name} already deleted"
    state["destroyed"] = True
    try:
        _delete_stack_and_wait(ctx, name)
    except Exception as exc:  # noqa: BLE001 -- reported, or raised from the cleanup
        leak = (
            f"stack {name} was not deleted: {_one_line(exc)} -- resources remain in the "
            "account"
        )
        if raise_on_leak:
            raise RuntimeError(leak) from exc
        state["leak"] = leak
        return leak
    return f"stack {name} deleted"
# ===== end flavor-specific deploy path =====


# Everything below is identical across every flavor of this application, so a divergence
# between them is attributable to the IaC path.

_EVIDENCE_CAP = 120
_HEADLINE_CAP = 280


def _one_line(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Collapse to a single capped line, so evidence cannot displace the summary line."""
    flat = " ".join(str(text).split())
    return flat[:cap]


class _Legs:
    """One PASS / FAIL / BLOCKED verdict per workflow leg, raised once at the end with the summary
    as the last line of the message."""

    def __init__(self, ctx, total: int) -> None:
        self._ctx = ctx
        self._total = total
        self._rows: list[tuple[str, str, str]] = []
        #: Legs that failed; drives the final raise.
        self._failed: set[str] = set()
        #: Legs that failed or were blocked; drives `requires` gating, so a leg never runs on
        #: state a blocked prerequisite never produced.
        self._not_passed: set[str] = set()

    def _record(self, name: str, verdict: str, evidence: str) -> None:
        self._rows.append((name, verdict, evidence))
        # Printed as it happens so a run killed mid-way still leaves a trail.
        print(f"[leg {len(self._rows)}/{self._total}] {verdict:7} {name}: {evidence}", flush=True)

    def step(self, name: str, fn, *, requires: tuple[str, ...] = ()):
        """Run leg *name*; record BLOCKED, not FAIL, when a prerequisite did not pass, so one
        broken hop does not count as a failure per downstream leg."""
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
        """A leg with nothing gradeable downstream (deploy, bootstrap): raise immediately rather
        than reporting N derived failures for a stack that never came up."""
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
        # Truncate the cells, never the headline, which must survive intact.
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


# --- the application under test, named identically in every flavor ---------------------------
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"
#: Stamped on every structured log line by both handlers, so a bare print cannot satisfy the logs leg.
_APP_TAG = "order-intake"
_METRIC_NAME = "OrdersFulfilled"
_STAGE_NAME = "live"
_ORDER_PATH = "orders"
#: The drift knob: the first apply asks for _BASE_MEMORY, the second for _DRIFT_MEMORY, and an
#: in-place modification of the intake function is the expected outcome.
_BASE_MEMORY = "128"
_DRIFT_MEMORY = "256"
#: A just-deployed stage answers these until it becomes routable, and a cold integration can 5xx
#: once while the function's first container starts, so _post_order retries them.
_ROUTING_WARMUP_CODES = (403, 404, 500, 502, 503, 504)

# Per-leg polling ceilings: the point past which a leg reports that the state never arrived, not
# the time it is expected to take.
_DEPLOY_BUDGET_S = 600.0  # a REST API + 2 functions + table + queue + mapping + alarm
_ROUTE_BUDGET_S = 180.0  # the stage becoming routable
_ROW_BUDGET_S = 60.0  # tolerance, not latency: put_item completes inside the handler
_WORKER_BUDGET_S = 180.0  # mapping poll interval + invocation + UpdateItem
_QUEUE_BUDGET_S = 120.0  # ApproximateNumberOfMessages is eventually consistent
_LOG_BUDGET_S = 240.0  # CloudWatch Logs ingestion, then FilterLogEvents visibility
_METRIC_BUDGET_S = 300.0  # PutMetricData -> GetMetricStatistics visibility
_ALARM_BUDGET_S = 420.0  # ~100s to leave INSUFFICIENT_DATA, plus a 60s period
#: After a transform re-expansion the event-source mapping can take well over 10 minutes to
#: deliver again, though it reads Enabled with no processing error.
_DRIFT_WORKER_BUDGET_S = 1800.0
_DESTROY_BUDGET_S = 180.0  # per gone-poll, AFTER the destroy returned: SQS takes up to 60s


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _new_state(ctx) -> dict[str, Any]:
    """Every name the deployed application uses, generated here so every flavor deploys the same
    named application and the legs need no flavor-specific output."""
    intake = _xname(ctx, "intake")
    worker = _xname(ctx, "worker")
    return {
        "TableName": _xname(ctx, "tbl"),
        "QueueName": _xname(ctx, "q"),
        "IntakeFunctionName": intake,
        "WorkerFunctionName": worker,
        "IntakeRoleName": f"{intake}-role",
        "WorkerRoleName": f"{worker}-role",
        "ApiName": _xname(ctx, "api"),
        "StageName": _STAGE_NAME,
        "AlarmName": _xname(ctx, "alarm"),
        "MetricNamespace": _xname(ctx, "ns"),
        "IntakeMemorySize": _BASE_MEMORY,
        "IntakeLogGroup": f"/aws/lambda/{intake}",
        "WorkerLogGroup": f"/aws/lambda/{worker}",
    }


#: The canonical parameter set, in CloudFormation parameter case.
_PARAM_KEYS = (
    "TableName",
    "QueueName",
    "IntakeFunctionName",
    "WorkerFunctionName",
    "IntakeRoleName",
    "WorkerRoleName",
    "ApiName",
    "StageName",
    "AlarmName",
    "MetricNamespace",
    "IntakeMemorySize",
)


def _params(state: dict[str, Any]) -> dict[str, str]:
    return {k: str(state[k]) for k in _PARAM_KEYS}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _apigw_url(ctx, api_id: str, stage: str, path: str = "") -> str:
    """Invoke URL for a deployed REST stage, via ctx.rest_api_url."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http_post(ctx, url: str, payload: dict, *, transport_error_is_fatal: bool = True):
    """POST *payload* as JSON to *url* -> (status, body); an HTTP error status is returned.

    `transport_error_is_fatal=False` is for the teardown leg, where nothing answering is expected.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"content-type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ssl_context(ctx.http_verify)))
    try:
        with opener.open(request, timeout=20) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, (exc.read() or b"").decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        if not transport_error_is_fatal:
            return None, f"transport error: {exc}"
        raise AssertionError(f"nothing answered at the stage endpoint {url}: {exc}") from exc


def _queue_url(ctx, state) -> str:
    """The queue's URL, resolved from the name the apply was given and cached in *state* -- the
    teardown leg needs it AFTER the queue is gone, when the name resolves to nothing."""
    url = state.get("QueueUrl")
    if not url:
        url = ctx.client("sqs").get_queue_url(QueueName=state["QueueName"])["QueueUrl"]
        state["QueueUrl"] = url
    return url


def _get_order(ctx, state, order_id: str):
    """The order row, read consistently, or None. A missing TABLE reads as a missing row so the
    teardown leg's polls and the wiring leg's polls can share one probe."""
    try:
        return (
            ctx.client("dynamodb")
            .get_item(
                TableName=state["TableName"],
                Key={"orderId": {"S": order_id}},
                ConsistentRead=True,
            )
            .get("Item")
        )
    except ClientError:
        return None


def _order_status(ctx, state, order_id: str):
    row = _get_order(ctx, state, order_id)
    return (row or {}).get("status", {}).get("S")


def _log_lines(ctx, log_group: str) -> list[dict[str, Any]]:
    """Every structured JSON line in *log_group*, decoded. Lambda's own START/END/REPORT lines are
    skipped rather than failing the read, and an absent group reads as no lines so a caller can poll
    for one appearing."""
    logs = ctx.client("logs")
    out: list[dict[str, Any]] = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(logGroupName=log_group):
            for event in page.get("events", []):
                message = (event.get("message") or "").strip()
                if not message.startswith("{"):
                    continue
                try:
                    row = json.loads(message)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    out.append(row)
    except ClientError:
        return []
    return out


def _post_order(ctx, state, *, timeout_s: float = _ROUTE_BUDGET_S):
    """POST /orders until the deployed stage answers 2xx; returns (order id, status, body)."""
    url = _apigw_url(ctx, state["ApiId"], state["StageName"], _ORDER_PATH)
    order_id = ctx.unique_name("order-")
    deadline = time.monotonic() + timeout_s
    status, body = None, ""
    while True:
        status, body = _http_post(ctx, url, {"orderId": order_id})
        if status is None or status not in _ROUTING_WARMUP_CODES:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    assert status is not None and 200 <= status < 300, (
        f"POST {url} never answered 2xx for order {order_id}; last status {status}: "
        f"{_one_line(body)}"
    )
    return order_id, status, body


def _mapping_diagnostic(ctx, state) -> str:
    """The worker's event-source mapping state and last processing result, to explain why the
    mapping is not draining."""
    try:
        mappings = ctx.client("lambda").list_event_source_mappings(
            FunctionName=state["WorkerFunctionName"]
        )["EventSourceMappings"]
    except ClientError as exc:
        return f"mapping unreadable: {exc}"
    if not mappings:
        return "no event-source mapping found for this function"
    return "; ".join(
        f"{m['UUID']}: State={m.get('State')} "
        f"LastProcessingResult={m.get('LastProcessingResult')} "
        f"BatchSize={m.get('BatchSize')}"
        for m in mappings
    )


def _wait_fulfilled(ctx, state, order_id: str, legs, *, timeout_s: float = _WORKER_BUDGET_S) -> str:
    """Wait for the worker to mark *order_id* fulfilled. The queue hop is asynchronous, so a state
    that never arrives is reported through never_reached rather than as a timeout."""
    started = time.monotonic()
    try:
        _poll_until(
            lambda: _order_status(ctx, state, order_id),
            lambda s: s == "fulfilled",
            timeout_s=timeout_s,
            interval_s=5.0,
            description=f"order {order_id} reaching fulfilled",
        )
    except AssertionError:
        legs.never_reached(
            f"order {order_id} never left {_order_status(ctx, state, order_id)!r}: the event-source "
            f"mapping did not drain {state['QueueName']} into {state['WorkerFunctionName']} -- "
            f"{_mapping_diagnostic(ctx, state)}",
            time.monotonic() - started,
        )
    return f"{order_id} fulfilled"


def _app_identity(ctx, state) -> dict[str, str]:
    """Identity tokens that survive a modification and change on a replacement: the table's id and
    creation time, the queue's creation time, and the event-source mapping's UUID."""
    table = ctx.client("dynamodb").describe_table(TableName=state["TableName"])["Table"]
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=_queue_url(ctx, state), AttributeNames=["CreatedTimestamp"]
    )["Attributes"]
    mappings = ctx.client("lambda").list_event_source_mappings(
        FunctionName=state["WorkerFunctionName"]
    )["EventSourceMappings"]
    return {
        "table-id": str(table.get("TableId") or table.get("TableArn")),
        "table-created": str(table.get("CreationDateTime")),
        "queue-created": str(attrs.get("CreatedTimestamp")),
        "mapping-uuid": ",".join(sorted(m["UUID"] for m in mappings)),
    }


#: A valid template, so UpdateStack on a deleted stack is refused as ``Stack [<name>] does not
#: exist`` rather than for the missing template.
_GONE_TEMPLATE = '{"Resources": {"Gone": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'

#: Bounded wait for a delete to reach its terminal not-found answer.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``.

    CloudWatch ResourceNotFound carries an empty message on AWS.
    """
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
_SQS_NF_MSG = "The specified queue does not exist."
_LOGS_NF_MSG = "The specified log group does not exist."


# --- the legs: identical bodies, identical names, in every flavor -----------------------------


def _deployed(ctx, state, legs) -> str:
    """The deploy leg, the only flavor-specific one: it calls `_apply`."""
    outputs = _apply(ctx, state, _params(state))
    api_id = (outputs or {}).get("ApiId")
    assert api_id, (
        f"the {_FLAVOR} apply reported no ApiId output; got {sorted(outputs or {})} -- every flavor "
        "of this application is required to report the REST API id the other legs address it through"
    )
    state["ApiId"] = api_id
    return f"{_FLAVOR}: ApiId={api_id} stage={state['StageName']} memory={state['IntakeMemorySize']}"


def _assert_order_persisted(ctx, state, legs) -> str:
    """POST /orders answers 2xx echoing the order id, and the row reads 'received'. put_item
    completes before the handler returns and the read is consistent, so a missing row is a FAIL."""
    _queue_url(ctx, state)
    order_id, status, body = _post_order(ctx, state)
    state["first_order"] = order_id
    try:
        echoed = json.loads(body)
    except ValueError:
        echoed = {}
    assert echoed.get("orderId") == order_id, (
        f"POST /orders answered {status} but the body did not echo order {order_id}: "
        f"{_one_line(body)}"
    )
    try:
        row = _poll_until(
            lambda: _get_order(ctx, state, order_id),
            lambda r: r is not None,
            timeout_s=_ROW_BUDGET_S,
            interval_s=3.0,
            description=f"the row for order {order_id}",
        )
    except AssertionError as exc:
        raise AssertionError(
            f"POST /orders answered {status} for order {order_id} but no row is readable in "
            f"{state['TableName']}: the stage answered without the intake function's PutItem "
            f"taking effect"
        ) from exc
    assert row.get("status", {}).get("S") == "received", (
        f"order {order_id} landed with status {row.get('status')}, expected 'received'"
    )
    return f"POST /orders {status} -> {order_id} at 'received' in {state['TableName']}"


def _assert_order_fulfilled(ctx, state, legs) -> str:
    """The event-source mapping drains the queued message into the worker, which marks the same
    order fulfilled, and the queue is left empty."""
    order_id = state["first_order"]
    _wait_fulfilled(ctx, state, order_id, legs)
    sqs = ctx.client("sqs")

    def _depth() -> int:
        attrs = sqs.get_queue_attributes(
            QueueUrl=_queue_url(ctx, state),
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
            ],
        )["Attributes"]
        return int(attrs.get("ApproximateNumberOfMessages", 0)) + int(
            attrs.get("ApproximateNumberOfMessagesNotVisible", 0)
        )

    started = time.monotonic()
    try:
        _poll_until(
            _depth,
            lambda d: d == 0,
            timeout_s=_QUEUE_BUDGET_S,
            interval_s=5.0,
            description=f"{state['QueueName']} draining",
        )
    except AssertionError:
        legs.never_reached(
            f"order {order_id} is fulfilled but {_depth()} message(s) remain on "
            f"{state['QueueName']}: the mapping did not delete what it delivered",
            time.monotonic() - started,
        )
    return f"order {order_id} fulfilled by {state['WorkerFunctionName']}, queue drained"


def _assert_structured_logs(ctx, state, legs) -> str:
    """Both declared log groups carry their handler's structured JSON line for the order: intake at
    'received', worker at 'fulfilled', both stamped app=order-intake."""
    logs = ctx.client("logs")
    order_id = state["first_order"]
    for group in (state["IntakeLogGroup"], state["WorkerLogGroup"]):
        existing = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        assert any(g["logGroupName"] == group for g in existing), (
            f"log group {group} does not exist: the apply declared it and its function has run"
        )
    wanted = (
        (state["IntakeLogGroup"], "intake", "received"),
        (state["WorkerLogGroup"], "worker", "fulfilled"),
    )

    def _hits() -> list[str]:
        return [
            stage
            for group, stage, status in wanted
            if any(
                row.get("app") == _APP_TAG
                and row.get("stage") == stage
                and row.get("orderId") == order_id
                and row.get("status") == status
                for row in _log_lines(ctx, group)
            )
        ]

    started = time.monotonic()
    try:
        hits = _poll_until(
            _hits,
            lambda h: len(h) == len(wanted),
            timeout_s=_LOG_BUDGET_S,
            interval_s=10.0,
            description="both structured JSON log lines",
        )
    except AssertionError:
        legs.never_reached(
            f"only {_hits()} of the intake/worker structured JSON lines for order {order_id} ever "
            f"appeared in {state['IntakeLogGroup']} / {state['WorkerLogGroup']}",
            time.monotonic() - started,
        )
    return f"structured {_APP_TAG} lines from {hits} for order {order_id}"


def _assert_metric_datapoint(ctx, state, legs) -> str:
    """The worker's custom OrdersFulfilled datapoint is readable in the per-run namespace."""
    cw = ctx.client("cloudwatch")

    def _total() -> float:
        stats = cw.get_metric_statistics(
            Namespace=state["MetricNamespace"],
            MetricName=_METRIC_NAME,
            StartTime=datetime.now(timezone.utc) - timedelta(minutes=45),
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum"],
        )
        return sum(float(d["Sum"]) for d in stats.get("Datapoints", []))

    started = time.monotonic()
    try:
        total = _poll_until(
            _total,
            lambda t: t >= 1.0,
            timeout_s=_METRIC_BUDGET_S,
            interval_s=10.0,
            description=f"a {_METRIC_NAME} datapoint",
        )
    except AssertionError:
        legs.never_reached(
            f"no {_METRIC_NAME} datapoint in namespace {state['MetricNamespace']} although the "
            f"worker fulfilled order {state['first_order']}",
            time.monotonic() - started,
        )
    return f"{_METRIC_NAME} Sum={total} in {state['MetricNamespace']}"


def _assert_alarm_transition(ctx, state, legs) -> str:
    """The declared alarm crosses INSUFFICIENT_DATA -> ALARM on the datapoint, and its state history
    records that transition."""
    cw = ctx.client("cloudwatch")
    name = state["AlarmName"]

    def _current():
        rows = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
        return rows[0]["StateValue"] if rows else None

    started = time.monotonic()
    try:
        _poll_until(
            _current,
            lambda s: s == "ALARM",
            timeout_s=_ALARM_BUDGET_S,
            interval_s=10.0,
            description=f"alarm {name} reaching ALARM",
        )
    except AssertionError:
        legs.never_reached(
            f"alarm {name} still reads {_current()!r} with a {_METRIC_NAME} datapoint over its "
            f"threshold of 1",
            time.monotonic() - started,
        )
    history = cw.describe_alarm_history(
        AlarmName=name, HistoryItemType="StateUpdate", MaxRecords=30
    ).get("AlarmHistoryItems", [])
    transitions = []
    for item in history:
        try:
            # The member is PascalCase "HistoryData"; only the keys inside its JSON are camelCase.
            data = json.loads(item.get("HistoryData") or "{}")
        except ValueError:
            continue
        transitions.append(
            (
                (data.get("oldState") or {}).get("stateValue"),
                (data.get("newState") or {}).get("stateValue"),
            )
        )
    assert ("INSUFFICIENT_DATA", "ALARM") in transitions, (
        f"alarm {name} reads ALARM but no StateUpdate history item records the "
        f"INSUFFICIENT_DATA->ALARM transition; history holds {transitions}"
    )
    return f"{name} INSUFFICIENT_DATA->ALARM recorded in {len(history)} StateUpdate item(s)"


def _assert_second_apply_modifies_in_place(ctx, state, legs) -> str:
    """A second apply with a raised IntakeMemorySize modifies the intake function in place: the
    table, queue and mapping identities survive, and a new order still flows end to end."""
    before = _app_identity(ctx, state)
    state["IntakeMemorySize"] = _DRIFT_MEMORY
    _apply(ctx, state, _params(state))
    after = _app_identity(ctx, state)
    memory = ctx.client("lambda").get_function_configuration(
        FunctionName=state["IntakeFunctionName"]
    )["MemorySize"]
    assert memory == int(_DRIFT_MEMORY), (
        f"the second apply did not take: {state['IntakeFunctionName']} reports MemorySize "
        f"{memory}, expected {_DRIFT_MEMORY}"
    )
    replaced = sorted(k for k in before if before[k] != after[k])
    assert not replaced, (
        f"the second apply REPLACED {replaced} (was "
        f"{ {k: before[k] for k in replaced} }, now { {k: after[k] for k in replaced} }) -- a "
        f"memory-size change is an in-place update of one function"
    )
    order_id, _, _ = _post_order(ctx, state)
    _wait_fulfilled(ctx, state, order_id, legs, timeout_s=_DRIFT_WORKER_BUDGET_S)
    return (
        f"MemorySize {_BASE_MEMORY}->{memory} in place, {len(before)} identity tokens stable, "
        f"order {order_id} still delivered"
    )


def _assert_destroy_stops_delivery(ctx, state, legs) -> str:
    """After the destroy the stack reads DELETE_COMPLETE, and every resource it provisioned is
    not-found, unlisted and refuses a mutation; the stage no longer answers 2xx."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    apigw = ctx.client("apigateway")
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    budget = _DESTROY_BUDGET_S
    # Resolved BEFORE the destroy: afterwards there is nothing left to resolve the names against.
    queue_url = _queue_url(ctx, state)
    url = _apigw_url(ctx, state["ApiId"], state["StageName"], _ORDER_PATH)
    api_id = state["ApiId"]
    root_id = next(
        r["id"] for r in _paged(apigw, "get_resources", "items", restApiId=api_id) if r["path"] == "/"
    )
    stack_name, stack_id = state["stack_name"], state["StackId"]

    destroyed = _destroy(ctx, state)

    # The stack: DELETE_COMPLETE tombstone by id, absent from the active listing, update refused.
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "DELETE_COMPLETE", f"{destroyed}, but stack {stack_name} reads {status}"
    active = [
        x["StackStatus"]
        for x in _paged(cfn, "list_stacks", "StackSummaries")
        if x["StackName"] == stack_name and x["StackStatus"] != "DELETE_COMPLETE"
    ]
    assert not active, f"ListStacks still lists {stack_name} as {active}"
    _refused(
        lambda: cfn.update_stack(StackName=stack_name, TemplateBody=_GONE_TEMPLATE),
        ("ValidationError",), 400, f"UpdateStack {stack_name}", f"Stack [{stack_name}] does not exist",
    )
    gone = ["stack"]

    table = state["TableName"]
    nf = ("ResourceNotFoundException",)
    _poll_refused(
        lambda: ddb.describe_table(TableName=table), nf, 400, f"DescribeTable {table}",
        f"Requested resource not found: Table: {table} not found", budget,
    )
    assert table not in _paged(ddb, "list_tables", "TableNames"), f"ListTables still lists {table}"
    _refused(
        lambda: ddb.put_item(TableName=table, Item={"orderId": {"S": "gone"}}),
        nf, 400, f"PutItem {table}", "Requested resource not found",
    )
    gone.append("table")

    queue = state["QueueName"]
    _poll_refused(
        lambda: sqs.get_queue_url(QueueName=queue), _SQS_NF, 400, f"GetQueueUrl {queue}", _SQS_NF_MSG, budget
    )
    listed = sqs.list_queues(QueueNamePrefix=queue).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == queue], f"ListQueues still lists {queue}"
    _refused(
        lambda: sqs.send_message(QueueUrl=queue_url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {queue}",
        _SQS_NF_MSG,
    )
    gone.append("queue")

    functions: set[str] = set()
    for key in ("IntakeFunctionName", "WorkerFunctionName"):
        fn = state[key]
        fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
        _poll_refused(
            lambda fn=fn: lam.get_function(FunctionName=fn), nf, 404, f"GetFunction {fn}",
            f"Function not found: {fn_arn}", budget,
        )
        if not functions:
            functions = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
        assert fn not in functions, f"ListFunctions still lists {fn}"
        _refused(
            lambda fn=fn: lam.invoke(FunctionName=fn, Payload=b"{}"), nf, 404, f"Invoke {fn}",
            f"Function not found: {fn_arn}:$LATEST",
        )
    gone.append("functions")

    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    for key in ("IntakeRoleName", "WorkerRoleName"):
        role = state[key]
        role_gone = f"The role with name {role} cannot be found."
        _poll_refused(
            lambda role=role: iam.get_role(RoleName=role), ("NoSuchEntity",), 404, f"GetRole {role}", role_gone, budget
        )
        roles = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix="/")}
        assert role not in roles, f"ListRoles still lists {role}"
        _refused(
            lambda role=role: iam.put_role_policy(RoleName=role, PolicyName="gone", PolicyDocument=doc),
            ("NoSuchEntity",), 404, f"PutRolePolicy {role}", role_gone,
        )
    gone.append("roles")

    api_gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _poll_refused(
        lambda: apigw.get_rest_api(restApiId=api_id), ("NotFoundException",), 404, f"GetRestApi {api_id}",
        api_gone, budget,
    )
    assert api_id not in {a["id"] for a in _paged(apigw, "get_rest_apis", "items")}, f"GetRestApis still lists {api_id}"
    _refused(
        lambda: apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="gone"),
        ("NotFoundException",), 404, f"CreateResource {api_id}", api_gone,
    )
    gone.append("api")

    alarm = state["AlarmName"]
    # DescribeAlarms has no not-found code: an empty result is the not-found answer.
    by_name = cw.describe_alarms(AlarmNames=[alarm])
    assert not by_name.get("MetricAlarms") and not by_name.get("CompositeAlarms"), f"{destroyed}, but alarm {alarm} still exists"
    prefixed = {a["AlarmName"] for a in cw.describe_alarms(AlarmNamePrefix=alarm).get("MetricAlarms", [])}
    assert alarm not in prefixed, f"DescribeAlarms(prefix) still lists {alarm}"
    _refused(
        lambda: cw.set_alarm_state(AlarmName=alarm, StateValue="OK", StateReason="gone"),
        ("ResourceNotFound",), 404, f"SetAlarmState {alarm}", "",
    )
    gone.append("alarm")

    for key in ("IntakeLogGroup", "WorkerLogGroup"):
        group = state[key]
        _poll_refused(
            lambda group=group: logs.describe_log_streams(logGroupName=group), nf, 400,
            f"DescribeLogStreams {group}", _LOGS_NF_MSG, budget,
        )
        groups = {g["logGroupName"] for g in logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])}
        assert group not in groups, f"DescribeLogGroups still lists {group}"
        _refused(
            lambda group=group: logs.put_log_events(
                logGroupName=group, logStreamName="gone",
                logEvents=[{"timestamp": int(time.time() * 1000), "message": "gone"}],
            ),
            nf, 400, f"PutLogEvents {group}", _LOGS_NF_MSG,
        )
    gone.append("log-groups")

    status, body = _http_post(
        ctx,
        url,
        {"orderId": ctx.unique_name("order-")},
        transport_error_is_fatal=False,
    )
    assert status is None or status >= 400, (
        f"POST {url} still answered {status} after {destroyed}: {_one_line(body)}"
    )
    served = "no listener" if status is None else str(status)
    return f"{destroyed}; gone: {','.join(gone)}; POST /{_ORDER_PATH} -> {served}"




if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
