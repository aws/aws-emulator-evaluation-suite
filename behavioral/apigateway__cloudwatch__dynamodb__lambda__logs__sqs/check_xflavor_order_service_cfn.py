"""xflavor-order-service-cfn."""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xflavor-order-service-cfn"
GROUP = "deployment-order"
SERVICES = ["apigateway", "cloudwatch", "dynamodb", "lambda", "logs", "sqs"]

_MODULE = Path(__file__).parent / "deployments" / "order_service_cfn.yaml"
#: Named in the deploy leg's evidence, so a leg summary says which IaC path produced it.
_FLAVOR = "cloudformation"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:eventing", "concern:metrics", "concern:negative-classes",
      "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """The order-intake application from a CloudFormation template serves POST /orders end to end through
    queue, logs, metrics and alarm, updates in place, refuses a denied UpdateItem with the exact code and
    message leaving the order unfulfilled, and stops answering once destroyed."""
    ctx.verify_account_safety()
    legs = _Legs(ctx, total=9)
    state = _new_state(ctx)
    # `requires` names the TRANSITIVE prerequisite set: a BLOCKED leg does not count as failed, so a
    # leg naming only its immediate predecessor would run on state a blocked leg never wrote.
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
        "denial",
        lambda: _assert_denied_worker_leaves_order_unfulfilled(ctx, state, legs),
        requires=("wiring", "worker"),
    )
    legs.step(
        "drift",
        lambda: _assert_second_apply_modifies_in_place(ctx, state, legs),
        requires=("wiring",),
    )
    # No `requires`: teardown correctness is independently gradeable, and running it in band is also
    # what keeps the destroy inside the check's own budget rather than the runner's 60s cleanup bound.
    legs.step("teardown", lambda: _assert_destroy_stops_delivery(ctx, state, legs))
    legs.verdict()


# ===== flavor-specific deploy path =====
# `_apply` and `_destroy` are the two seams the shared legs call; everything else is independent of
# how the application is deployed.
_CAPABILITIES = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"]


def _apply(ctx, state, params) -> dict[str, str]:
    """Deploy the hand-written order_service_cfn.yaml. The first call creates the stack, the second
    updates it -- so the drift leg exercises a real CloudFormation update of a live stack rather
    than a fresh deployment that happens to differ."""
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
    """The first resource-level failure reason on the stack, which is the only thing that says WHY.
    "ended in ROLLBACK_COMPLETE" names neither a resource nor a cause, and the leg summary the
    scorer keeps is one line."""
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
    """create_stack and wait. The stack name and cleanup registration go through *state*, so the
    teardown leg and the registered cleanup never both delete the stack; the wait ceiling is the
    suite's deploy budget.

    `timeout_s` is required rather than defaulted: the budget constants live in the SHARED
    region below, and a default argument is evaluated at definition time -- naming one here
    would be a NameError on import, which is the one way this file can fail before it runs."""
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
    cfn.create_stack(**kwargs)
    state["stack_name"] = name
    ctx.on_cleanup(lambda: _destroy(ctx, state, raise_on_leak=True))
    return _wait_stack(ctx, name, {"CREATE_COMPLETE"}, timeout_s)


def _update_cfn(ctx, state, template, *, timeout_s, parameters=None):
    """The second apply. `update_stack` rather than a change set: the drift leg asserts the OUTCOME
    -- modified versus replaced -- against the resources themselves, and a change set would only
    report CloudFormation's own prediction of it."""
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
    """Delete the stack and wait within the deploy budget, not 120s: a
    stack holding a REST API, two functions, a table and a queue does not finish deleting in 120s,
    and a poll that gives up early leaves the teardown leg asserting against a half-deleted stack."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status() -> str:
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            # DescribeStacks answers a deleted stack with ValidationError "... does not exist".
            if exc.response.get("Error", {}).get("Code") == "ValidationError" and (
                "does not exist" in str(exc)
            ):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=_DEPLOY_BUDGET_S,
        interval_s=10.0,
        description=f"delete stack {stack_name}",
    )


def _destroy(ctx, state, *, raise_on_leak: bool = False) -> str:
    """Delete the stack, once. Idempotent, because the teardown leg calls it in band and the
    registered cleanup calls it again on the way out.

    In band (the default) a failed delete is returned rather than raised:
    the teardown leg grades the RESOURCES, which is where a half-deleted stack shows up regardless.
    The registered cleanup passes ``raise_on_leak=True``, so a failed delete -- its own, or the
    in-band one it finds recorded -- raises and lands in the runner's cleanup detail."""
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
        return f"stack {name} delete FAILED: {leak}"
    return f"stack {name} deleted"
# ===== end flavor-specific deploy path =====


# The legs below do not depend on the deploy path; only `_apply` and `_destroy` do.

_EVIDENCE_CAP = 120
_HEADLINE_CAP = 280


def _one_line(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Collapse to a single line. Load-bearing: a leg's evidence must not be able to introduce a
    newline, or IT becomes the last line of the detail and displaces the summary _err_line reads."""
    flat = " ".join(str(text).split())
    return flat[:cap]


class _Legs:
    """One PASS / FAIL / BLOCKED verdict per workflow leg, raised ONCE at the end.

    The summary is the LAST line of the message on purpose: a report that keeps only the last line
    of the detail still carries every leg's verdict.
    """

    def __init__(self, ctx, total: int) -> None:
        self._ctx = ctx
        self._total = total
        self._rows: list[tuple[str, str, str]] = []
        #: Legs that FAILED. Drives the final raise.
        self._failed: set[str] = set()
        #: Legs that did not PASS -- failed OR blocked. Drives `requires` gating, and it must be a
        #: SEPARATE set from `_failed`: gating on `_failed` alone means a leg whose prerequisite was
        #: BLOCKED (not failed) still runs, against state the blocked leg never produced. That turns
        #: one upstream break into a cascade of misleading FAILs two hops down, which is exactly what
        #: BLOCKED exists to prevent. Keeping both sets also means `requires` names the IMMEDIATE
        #: prerequisite; the transitive closure falls out for free.
        self._not_passed: set[str] = set()

    def _record(self, name: str, verdict: str, evidence: str) -> None:
        self._rows.append((name, verdict, evidence))
        # Printed as it happens so a green run still says which legs it actually proved, and so a
        # run killed by the budget leaves a trail the summary never got to emit.
        print(f"[leg {len(self._rows)}/{self._total}] {verdict:7} {name}: {evidence}", flush=True)

    def step(self, name: str, fn, *, requires: tuple[str, ...] = ()):
        """Run leg *name*; record BLOCKED when a prerequisite already failed.

        BLOCKED rather than FAIL keeps one broken hop from being reported again as a failure of
        every downstream leg.
        """
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
        # The cells are truncated, NEVER the headline: the headline is the only thing _err_line
        # keeps, so it must survive intact.
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
#: Stamped on every structured log line by both handlers. Asserted, so a bare `print` of the order
#: id cannot satisfy the logs leg -- the line has to be the JSON document the handler emits.
_APP_TAG = "order-intake"
_METRIC_NAME = "OrdersFulfilled"
_STAGE_NAME = "live"
_ORDER_PATH = "orders"
#: The drift knob: the first apply asks for _BASE_MEMORY, the second for _DRIFT_MEMORY, and an
#: in-place modification of the intake function is the expected outcome.
_BASE_MEMORY = "128"
_DRIFT_MEMORY = "256"
#: A just-deployed stage answers these until it becomes routable, and a cold integration can 5xx
#: once while the function's first container starts, so _post_order retries them instead of
#: reporting the first one as the answer.
_ROUTING_WARMUP_CODES = (403, 404, 500, 502, 503, 504)

# Per-leg polling ceilings: each is the point past which a leg reports that the state never
# arrived, not the time it is expected to take.
_DEPLOY_BUDGET_S = 600.0  # a REST API + 2 functions + table + queue + mapping + alarm
_ROUTE_BUDGET_S = 180.0  # the stage becoming routable
_ROW_BUDGET_S = 60.0  # tolerance, not latency: put_item completes inside the handler
_WORKER_BUDGET_S = 180.0  # mapping poll interval + invocation + UpdateItem
_QUEUE_BUDGET_S = 120.0  # ApproximateNumberOfMessages is eventually consistent
_LOG_BUDGET_S = 240.0  # CloudWatch Logs ingestion, then FilterLogEvents visibility
_METRIC_BUDGET_S = 300.0  # PutMetricData -> GetMetricStatistics visibility
_ALARM_BUDGET_S = 420.0  # ~101s measured to leave INSUFFICIENT_DATA, plus a 60s period
#: IAM Deny propagation on an already-live role, then one more end-to-end hop: eventually consistent,
#: with a tail far longer than its typical case. Used for both the attach- and the drop-side race.
_DENIAL_BUDGET_S = 900.0
#: The worker's own UpdateItem refusal under the explicit Deny, as AWS returns it: the principal is
#: the assumed-role session named after the worker function, the resource is the table ARN.
_DENY_CODE = "AccessDeniedException"
_DENY_MESSAGE = (
    "User: arn:aws:sts::{account}:assumed-role/{role}/{function} is not authorized to perform: "
    "dynamodb:UpdateItem on resource: arn:aws:dynamodb:{region}:{account}:table/{table} "
    "with an explicit deny in an identity-based policy"
)
_DESTROY_BUDGET_S = 180.0  # per gone-poll, AFTER the destroy returned: SQS takes up to 60s
#: Longest path: deploy 600 + wiring 240 + worker 300 + logs 240 + metrics 300 + alarm 420 +
#: denial 1800 (attach-race 900 + drop-race 900) + drift 960 + teardown (600 destroy + 3x180
#: gone-polls) = ~6000s of ceilings.


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _new_state(ctx) -> dict[str, Any]:
    """Every name the deployed application uses. Generated HERE rather than by the IaC so the four
    flavors deploy the same named application and the legs can address it without reading a
    flavor-specific output, and prefixed with `sim2real-xsvc-` so cleanup can find every resource
    by name."""
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


#: The one canonical parameter set, spelled in CloudFormation parameter case. The cfn, sam and cdk
#: flavors consume it as-is; the terraform flavor maps it to snake_case variable names inside its own
#: `_apply`, which is where a per-flavor difference belongs.
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
    """Invoke URL for a deployed REST stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route
    (both via ctx.rest_api_url)."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _http_post(ctx, url: str, payload: dict, *, transport_error_is_fatal: bool = True):
    """POST *payload* as JSON to *url*, returning (status, body). An HTTP error status is an ANSWER
    and is returned; only a transport failure is a verdict.

    `transport_error_is_fatal=False` is for the teardown leg, where nothing answering is the
    expected outcome and must not read as a data-plane gap.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
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
            f"mapping did not drain {state['QueueName']} into {state['WorkerFunctionName']}",
            time.monotonic() - started,
        )
    return f"{order_id} fulfilled"


def _app_identity(ctx, state) -> dict[str, str]:
    """Identity tokens that survive a MODIFICATION and change on a REPLACEMENT: the table's own id
    and creation time, the queue's creation time, and the event-source mapping's UUID. The mapping
    is the sharpest of the three -- a flavor that replaces the worker function replaces the mapping
    with it, and the wiring silently comes back under a new identity."""
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


def _drop_role_policy(ctx, role_name: str, policy_name: str) -> None:
    """Remove the injected Deny; one already removed is fine, any other error raises. Run in the
    denial leg's `finally` AND registered as a cleanup: an attached Deny would make every later leg
    fail for a reason the denial leg created, and a leg dying mid-way must not leave one behind."""
    found = sys.exc_info()[1]
    try:
        ctx.client("iam").delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise RuntimeError(
                (f"{found!r}; " if found else "")
                + f"teardown could not remove Deny policy {policy_name} from {role_name}: {exc}"
            ) from exc


def _is_gone(probe) -> bool:
    """True when *probe* raises its service's not-found error. Any OTHER ClientError is a different
    fact and must not read as 'deleted' -- that is how a teardown assertion passes on an
    AccessDenied."""
    try:
        probe()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        return any(
            token in code
            for token in ("NotFound", "ResourceNotFoundException", "NonExistentQueue", "DoesNotExist")
        )
    return False


# --- the legs: identical bodies, identical names, in all four flavors -------------------------


def _deployed(ctx, state, legs) -> str:
    """The deploy leg. The ONLY leg whose mechanism is flavor-specific: it calls `_apply`, which is
    the seam between the four files. `legs.hard` rather than `legs.step`, because nothing downstream
    is gradeable against an application that never came up."""
    outputs = _apply(ctx, state, _params(state))
    api_id = (outputs or {}).get("ApiId")
    assert api_id, (
        f"the {_FLAVOR} apply reported no ApiId output; got {sorted(outputs or {})} -- every flavor "
        "of this application is required to report the REST API id the other legs address it through"
    )
    state["ApiId"] = api_id
    return f"{_FLAVOR}: ApiId={api_id} stage={state['StageName']} memory={state['IntakeMemorySize']}"


def _assert_order_persisted(ctx, state, legs) -> str:
    """POST /orders answers 2xx echoing the order id, and the intake function's PutItem is readable
    at 'received' -- the API Gateway -> Lambda -> DynamoDB half of the application.

    A missing row is asserted as a FAIL rather than reported through never_reached: put_item
    completes inside the handler before it returns the body the stage just relayed, and the read is
    consistent, so there is no window in which the absence could be provisioning latency."""
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
    """The end-to-end hop nothing before it establishes: the message the intake function put on the
    queue is drained by the event-source mapping into the worker, which marks the SAME order
    fulfilled -- and the mapping then deletes what it delivered, so the queue is left empty."""
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
    """Both DECLARED log groups exist and carry their handler's structured JSON line for the order
    the earlier legs proved: the intake side at 'received', the worker side at 'fulfilled', both
    stamped app=order-intake so a bare print of the order id cannot satisfy this.

    The groups are declared by the IaC rather than left to Lambda's implicit creation, which is what
    makes their existence assertable here and their absence assertable after the destroy."""
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
    """The worker's custom OrdersFulfilled datapoint is readable in the namespace the apply gave it.
    A per-run namespace, so no other check's data can satisfy this."""
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
    """The alarm the apply declared crosses INSUFFICIENT_DATA -> ALARM on the datapoint, AND its
    state history RECORDS that transition.

    Both halves matter. Reading the current state alone cannot distinguish an alarm that evaluated
    from one whose state was assigned, and DescribeAlarmHistory is where the evaluation leaves its
    trace. The alarm has no actions: polling its own state keeps the application free of an SNS
    topic, so all four flavors deploy the same thing."""
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
            # "HistoryData", PascalCase: botocore returns the modelled member name
            # (DescribeAlarmHistory -> AlarmHistoryItems[].HistoryData). The camelCase spelling
            # matched nothing, so every item parsed as {} and `transitions` came out [(None, None)]
            # -- the assertion below then failed on an alarm that HAD transitioned correctly, in all
            # four flavors at once. Only the keys INSIDE the JSON string are camelCase.
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


def _post_fresh_until(ctx, state, *, want_fulfilled: bool, deadline: float, label: str):
    """Post FRESH orders, one per attempt, until one's outcome matches *want_fulfilled* or
    *deadline* (a `time.monotonic()` timestamp) passes. Returns `(order_id, status, denials,
    attempts)`, with `status` `None` if the deadline was reached with no matching outcome.

    Never re-polls a stale order: once SQS has delivered a message the worker consumes it (fulfilled
    or denied) permanently, so only a NEW order can prove the NEXT state. Each attempt is therefore a
    real repeated observation of a live wiring, not a blind sleep -- the right shape for racing an
    IAM policy change that is only eventually consistent (measured on real AWS: attaching a Deny to
    an already-live role and probing 0.4s later lost the race and was fulfilled 0.6s after that; the
    same race runs in reverse when the Deny is dropped)."""
    attempt = 0
    order_id, status, denials = None, None, []
    while True:
        attempt += 1
        order_id, _, _ = _post_order(ctx, state)

        def _outcome():
            denials_ = [
                row
                for row in _log_lines(ctx, state["WorkerLogGroup"])
                if row.get("orderId") == order_id and row.get("status") == "denied"
            ]
            return _order_status(ctx, state, order_id), denials_

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return order_id, None, [], attempt
        try:
            status, denials = _poll_until(
                _outcome,
                lambda r: r[0] == "fulfilled" or bool(r[1]),
                timeout_s=min(40.0, remaining),
                interval_s=5.0,
                description=f"{label} (attempt {attempt})",
            )
        except AssertionError:
            return order_id, None, [], attempt
        if (status == "fulfilled") == want_fulfilled:
            return order_id, status, denials, attempt
        # Outcome didn't match what this call is waiting for yet -- the IAM change (attach or
        # drop) had not propagated for this attempt. Retry with a fresh order.


def _assert_denied_worker_leaves_order_unfulfilled(ctx, state, legs) -> str:
    """With an explicit Deny on dynamodb:UpdateItem attached to the worker's role, a new order must
    produce BOTH the specific denial and the effect-absent: the worker logs AccessDeniedException with AWS's exact message
    for that order, and the row stays at 'received' instead of reaching 'fulfilled'. The deny is
    then dropped and PROVEN dropped: a fresh order is fulfilled again, closing the refusal's sixth
    beat (restore, then re-assert success) instead of leaving the restore unasserted.

    Injected through IAM on the ALREADY-DEPLOYED role rather than by applying a second, broken
    module: the whole point of this set is that the four checks differ only in their deploy path, so
    a negative needing a flavor-specific second apply would put the difference back into a leg. An
    explicit Deny also decides the request whatever the role's Allow says, which keeps the assertion
    about the evaluation rather than about which flavor wrote which policy document.

    The control for it is the `worker` leg this one requires: the same code path fulfilled an order
    moments earlier, so a row left at 'received' here cannot be a broken application.

    Both the attach and the drop race IAM's eventual consistency on this ALREADY-LIVE role, so both
    halves use `_post_fresh_until` rather than trusting the first probe: without the restore proof,
    a later leg's own order can silently inherit a Deny that had not finished propagating away, and
    report a wiring break under a name that has nothing to do with IAM."""
    role = state["WorkerRoleName"]
    policy_name = "sim2real-xsvc-deny-updateitem"
    ctx.client("iam").put_role_policy(
        RoleName=role,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Deny", "Action": "dynamodb:UpdateItem", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _drop_role_policy(ctx, role, policy_name))
    try:
        deny_deadline = time.monotonic() + _DENIAL_BUDGET_S
        order_id, status, denials, attempt = _post_fresh_until(
            ctx,
            state,
            want_fulfilled=False,
            deadline=deny_deadline,
            label=f"the worker acting on a denied order under a Deny on {role}",
        )
        if status is None:
            legs.never_reached(
                f"order {order_id} (attempt {attempt}) was neither fulfilled nor reported denied by "
                f"{state['WorkerFunctionName']} under an explicit Deny on dynamodb:UpdateItem",
                _DENIAL_BUDGET_S,
            )
        assert status != "fulfilled", (
            f"the worker's role {role} carries an explicit Deny on dynamodb:UpdateItem, yet order "
            f"{order_id} was still marked fulfilled after {attempt} attempt(s) across "
            f"{_DENIAL_BUDGET_S:.0f}s -- the deny was never evaluated, not merely slow to propagate"
        )
        codes = sorted({str(d.get("code")) for d in denials})
        assert codes == [_DENY_CODE], (
            f"the worker reported a failed UpdateItem for order {order_id} but not "
            f"{_DENY_CODE}: {codes}"
        )
        expected_message = _DENY_MESSAGE.format(
            account=ctx.account,
            region=ctx.region,
            role=role,
            function=state["WorkerFunctionName"],
            table=state["TableName"],
        )
        messages = sorted({str(d.get("message")) for d in denials})
        assert messages == [expected_message], (
            f"the worker's denied UpdateItem for order {order_id} carried {messages}, expected "
            f"exactly {expected_message!r}"
        )
        assert status == "received", (
            f"order {order_id} is at {status!r}, expected the pre-worker 'received' -- the denied "
            f"UpdateItem changed the row anyway"
        )
    finally:
        _drop_role_policy(ctx, role, policy_name)

    restore_deadline = time.monotonic() + _DENIAL_BUDGET_S
    restored_id, restored_status, _, restore_attempt = _post_fresh_until(
        ctx,
        state,
        want_fulfilled=True,
        deadline=restore_deadline,
        label=f"order fulfilled again after the deny on {role} was dropped",
    )
    assert restored_status == "fulfilled", (
        f"after dropping the Deny on {role}, order {restored_id} was never fulfilled across "
        f"{restore_attempt} attempt(s)/{_DENIAL_BUDGET_S:.0f}s -- the restore did not take effect"
    )
    return (
        f"{order_id} denied {codes} and left at {status!r} (attempt {attempt}); restore confirmed "
        f"by {restored_id} (attempt {restore_attempt})"
    )


def _assert_second_apply_modifies_in_place(ctx, state, legs) -> str:
    """A SECOND apply with a raised IntakeMemorySize must MODIFY the intake function, not replace the
    application around it: the change has to land, the table's identity and the queue's creation
    time and the event-source mapping's UUID all have to survive it, and the wiring has to still
    deliver a new order end to end afterwards.

    Near-zero coverage today, and the property is exactly what an emulator gets wrong quietly -- a
    replace-instead-of-update leaves an application that still works and has lost its data."""
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
    _wait_fulfilled(ctx, state, order_id, legs)
    return (
        f"MemorySize {_BASE_MEMORY}->{memory} in place, {len(before)} identity tokens stable, "
        f"order {order_id} still delivered"
    )


def _assert_destroy_stops_delivery(ctx, state, legs) -> str:
    """After the destroy the table, the queue and the intake function are GONE, the alarm is gone,
    and the stage no longer answers -- so a POST can no longer produce a row, which "the API returns
    an error" does not establish on its own.

    The destroy runs HERE, in band, rather than being left to the registered cleanup: the runner
    bounds its cleanup phase at 60s, far below a stack delete or a `terraform destroy`, so a
    teardown asserted only through cleanup is a teardown nobody grades. The registered cleanup
    remains the safety net for a run that dies before this leg, and `_destroy` is idempotent so it
    is a no-op after it."""
    ddb = ctx.client("dynamodb")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    # Resolved BEFORE the destroy: afterwards there is nothing left to resolve the names against.
    queue_url = _queue_url(ctx, state)
    url = _apigw_url(ctx, state["ApiId"], state["StageName"], _ORDER_PATH)

    destroyed = _destroy(ctx, state)

    started = time.monotonic()
    gone: list[str] = []
    for label, probe in (
        ("table", lambda: ddb.describe_table(TableName=state["TableName"])),
        (
            "queue",
            lambda: sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["QueueArn"]
            ),
        ),
        ("intake", lambda: lam.get_function(FunctionName=state["IntakeFunctionName"])),
    ):
        try:
            _poll_until(
                lambda: _is_gone(probe),
                lambda g: g,
                timeout_s=_DESTROY_BUDGET_S,
                interval_s=5.0,
                description=f"the {label} disappearing",
            )
        except AssertionError:
            legs.never_reached(
                f"{destroyed}, but the {label} is still there",
                time.monotonic() - started,
            )
        gone.append(label)

    alarms = ctx.client("cloudwatch").describe_alarms(AlarmNames=[state["AlarmName"]])[
        "MetricAlarms"
    ]
    assert not alarms, f"{destroyed}, but alarm {state['AlarmName']} still exists"
    gone.append("alarm")

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
