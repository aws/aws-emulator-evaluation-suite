"""cfn-change-set-queue-worker-update-workflow."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-change-set-queue-worker-update-workflow"

GROUP = "change_sets"

SERVICES = ["cloudformation", "cloudwatch", "lambda", "logs", "sqs", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"

_WORKER_TEMPLATE = "queue-worker.yaml"
_BROKEN_TEMPLATE = "queue-worker-no-config-permission.yaml"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A change set predicts an update to an SQS-triggered Lambda worker (one replace, one in-place)
    and executing it does exactly that; alarm, drift, a denied role and teardown are also checked.
    """
    legs = _Legs(ctx, total=10)

    queue_name = _xname(ctx, "workq")
    fn_name = _xname(ctx, "worker")
    alarm_name = _xname(ctx, "alarm")
    log_group = f"/aws/lambda/{fn_name}"
    namespace = "SimParity/QueueWorker"
    metric_name = "MessagesProcessed"
    cfg_v1 = _xname(ctx, "cfg")
    cfg_v2 = _xname(ctx, "cfg")

    # Registered BEFORE the deploy so LIFO runs them AFTER the stack delete: a belt-and-braces sweep
    # for a stack that ends DELETE_FAILED and strands the two resources with a caller-chosen name.
    for cfg in (cfg_v1, cfg_v2):
        ctx.on_cleanup(lambda n=cfg: _swallow(lambda: ctx.client("ssm").delete_parameter(Name=n)))
    ctx.on_cleanup(
        lambda: _swallow(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))
    )

    params_v1 = {
        "QueueName": queue_name,
        "FunctionName": fn_name,
        "WorkerConfigParamName": cfg_v1,
        "WorkerConfigValue": "tier-a",
        "LogLevel": "INFO",
        "MetricNamespace": namespace,
        "MetricName": metric_name,
        "AlarmName": alarm_name,
        "AlarmThreshold": "1",
    }
    params_v2 = dict(params_v1, WorkerConfigParamName=cfg_v2, WorkerConfigValue="tier-b", LogLevel="DEBUG")

    stack = legs.hard(
        "deploy",
        lambda: _deploy_cfn(
            ctx,
            (DEPLOYMENTS / _WORKER_TEMPLATE).read_text(),
            parameters=params_v1,
            timeout_s=600.0,
        ),
    )
    stack_name = stack["stack_name"]
    queue_url = stack["outputs"]["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_stack_deadline(ctx, stack_name, timeout_s=900.0))

    state: dict[str, Any] = {}

    legs.step("wiring", lambda: _assert_message_consumed(ctx, queue_url, log_group, state))
    legs.step(
        "logs",
        lambda: _assert_structured_line(ctx, log_group, state, expect_config="tier-a", expect_level="INFO"),
        requires=("wiring",),
    )
    legs.step(
        "metrics",
        lambda: _assert_metric_datapoint(ctx, namespace, metric_name, fn_name, legs),
        requires=("wiring",),
    )
    legs.step(
        "alarm",
        lambda: _assert_alarm_reaches_alarm(ctx, alarm_name, queue_url, legs),
        requires=("metrics",),
    )
    legs.step(
        "changeset",
        lambda: _assert_change_set_predicts(
            ctx, stack_name, params_v2, cfg_v1, cfg_v2, fn_name, queue_url, state
        ),
    )
    legs.step(
        "executed",
        lambda: _assert_reality_matches_prediction(
            ctx, stack_name, cfg_v1, cfg_v2, fn_name, queue_url, log_group, state
        ),
        requires=("changeset",),
    )
    legs.step("drift", lambda: _assert_drift_reports_out_of_band_write(ctx, stack_name, cfg_v2), requires=("executed",))
    legs.step("denial", lambda: _assert_missing_config_permission_denies(ctx, namespace, metric_name))
    legs.step(
        "teardown",
        lambda: _assert_teardown_stops_delivery(ctx, stack_name, queue_name, queue_url, fn_name, alarm_name, log_group),
    )
    legs.verdict()


_EVIDENCE_CAP = 120
_HEADLINE_CAP = 280


def _one_line(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Collapse to one line, so evidence cannot displace the summary as the detail's last line."""
    flat = " ".join(str(text).split())
    return flat[:cap]


class _Legs:
    """One PASS / FAIL / BLOCKED verdict per workflow leg, raised once at the end."""

    def __init__(self, ctx, total: int) -> None:
        self._ctx = ctx
        self._total = total
        self._rows: list[tuple[str, str, str]] = []
        #: Legs that FAILED. Drives the final raise.
        self._failed: set[str] = set()
        #: Legs that did not PASS (failed or blocked). Drives `requires` gating, so a leg whose
        #: prerequisite was BLOCKED is blocked too rather than run against state never produced.
        self._not_passed: set[str] = set()

    def _record(self, name: str, verdict: str, evidence: str) -> None:
        self._rows.append((name, verdict, evidence))
        # Printed as it happens so a run killed by the budget still leaves a trail.
        print(f"[leg {len(self._rows)}/{self._total}] {verdict:7} {name}: {evidence}", flush=True)

    def step(self, name: str, fn, *, requires: tuple[str, ...] = ()):
        """Run leg *name*; record BLOCKED when an immediate prerequisite did not pass.

        BLOCKED, not FAIL, so one broken hop is not counted again for every downstream leg.
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
        """A leg with nothing gradeable downstream (deploy, bootstrap): raise immediately."""
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


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_NO_SUCH_QUEUE_MESSAGE = "The specified queue does not exist."
_PARAMETER_NOT_FOUND_MESSAGE = ""  # SSM sends ParameterNotFound with an empty message
_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _swallow(fn):
    """Run fn(), tolerating only the not-found answers ParameterNotFound and ResourceNotFoundException."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ParameterNotFound", "ResourceNotFoundException"):
            raise


def _stack_status(cfn, name: str) -> str:
    """The stack's status, or "GONE" when DescribeStacks answers that it does not exist."""
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationError" and err.get("Message") == f"Stack with id {name} does not exist":
            return "GONE"
        raise


def _delete_stack_deadline(ctx, name: str, *, timeout_s: float) -> None:
    """delete_stack, then wait up to timeout_s (longer than the 120s of _delete_stack_and_wait), raising
    on DELETE_FAILED or any error but not-found, so a stack whose delete outlives 120s (an ESM and a
    function take a while) is waited out rather than left mid-DELETE_IN_PROGRESS."""
    cfn = ctx.client("cloudformation")
    try:
        if _stack_status(cfn, name) == "GONE":
            return
        cfn.delete_stack(StackName=name)
        final = _poll_until(
            lambda: _stack_status(cfn, name),
            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
            timeout_s=timeout_s,
            interval_s=2.0,
            description=f"delete stack {name}",
        )
        if final == "DELETE_FAILED":
            raise RuntimeError(
                f"stack {name} ended DELETE_FAILED — its resources are stranded"
            )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {name} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


def _log_messages(ctx, group: str) -> list[str]:
    """Every log message in the group, across streams. filter_log_events (not get_log_events) so the
    caller does not have to guess Lambda's stream name, and with no filterPattern so the matching is
    done in Python rather than depending on filter-pattern fidelity."""
    logs = ctx.client("logs")
    out: list[str] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"logGroupName": group, "limit": 200}
        if token:
            kwargs["nextToken"] = token
        try:
            page = logs.filter_log_events(**kwargs)
        except ClientError:
            return out
        out.extend(e.get("message", "") for e in page.get("events", []))
        token = page.get("nextToken")
        if not token or len(out) >= 2000:
            return out


def _json_lines(messages: list[str]) -> list[dict]:
    """The subset of log messages that parse as a JSON object (the worker's structured lines)."""
    parsed = []
    for m in messages:
        text = m.strip()
        if not text.startswith("{"):
            continue
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(doc, dict):
            parsed.append(doc)
    return parsed


def _queue_depth(ctx, queue_url: str) -> tuple[int, int]:
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (
        int(attrs["ApproximateNumberOfMessages"]),
        int(attrs["ApproximateNumberOfMessagesNotVisible"]),
    )


def _physical_ids(ctx, stack_name: str) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    out: dict[str, str] = {}
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.list_stack_resources(**kwargs)
        for r in page["StackResourceSummaries"]:
            out[r["LogicalResourceId"]] = r.get("PhysicalResourceId", "")
        token = page.get("NextToken")
        if not token:
            return out


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _expect_error(fn, expected: tuple[tuple[str, ...], str], what: str) -> str:
    """Call fn() expecting the (codes, message) pair `expected`: one of the codes carrying exactly
    the message; returns the code. A SUCCESS is the interesting failure."""
    try:
        fn()
    except ClientError as exc:
        code = _error_code(exc)
        if code not in expected[0]:
            raise AssertionError(f"{what}: expected one of {expected[0]}, got {code}") from exc
        got = exc.response.get("Error", {}).get("Message")
        if got != expected[1]:
            raise AssertionError(f"{what}: expected message {expected[1]!r}, got {got!r}") from exc
        return code
    raise AssertionError(f"{what}: the call SUCCEEDED; expected one of {expected[0]}")


# ---- legs ----------------------------------------------------------------------------------------


def _assert_message_consumed(ctx, queue_url: str, log_group: str, state: dict) -> str:
    """The event source mapping the template declared really polls: a sent message disappears from
    the queue and the worker's own log group names its messageId."""
    sqs = ctx.client("sqs")
    marker = _xname(ctx, "msg")
    sent = sqs.send_message(QueueUrl=queue_url, MessageBody=marker)
    state["marker_v1"] = marker
    state["message_id_v1"] = sent["MessageId"]
    docs = _poll_until(
        lambda: [d for d in _json_lines(_log_messages(ctx, log_group)) if d.get("body") == marker],
        lambda ds: bool(ds),
        timeout_s=300.0,
        interval_s=2.0,
        description=f"worker log line for message {marker}",
    )
    state["line_v1"] = docs[0]
    visible, in_flight = _poll_until(
        lambda: _queue_depth(ctx, queue_url),
        lambda d: d == (0, 0),
        timeout_s=180.0,
        interval_s=2.0,
        description=f"queue {queue_url} drained after the worker deleted the message",
    )
    return f"msg {marker} processed, queue depth {visible}/{in_flight}"


def _assert_structured_line(ctx, log_group: str, state: dict, *, expect_config: str, expect_level: str) -> str:
    """The declared log group (not one Lambda invented) carries the structured line, and the fields
    prove the worker read its configuration out of the SSM parameter the template created."""
    groups = ctx.client("logs").describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
    declared = [g for g in groups if g["logGroupName"] == log_group]
    assert declared, f"the template's AWS::Logs::LogGroup {log_group} does not exist"
    assert declared[0].get("retentionInDays") == 7, (
        f"RetentionInDays from the template did not reach the log group: {declared[0]!r}"
    )
    line = state["line_v1"]
    assert line.get("event") == "work.processed", line
    assert line.get("level") == expect_level, line
    assert line.get("config") == expect_config, (
        f"the worker logged config={line.get('config')!r}; the SSM parameter holds {expect_config!r}"
    )
    assert line.get("messageId") == state["message_id_v1"], line
    assert line.get("requestId"), f"no Lambda requestId in the structured line: {line!r}"
    return f"structured line config={line['config']} level={line['level']}"


def _metric_sum(ctx, namespace: str, metric_name: str, worker: str) -> float:
    now = time.time()
    points = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{"Name": "Worker", "Value": worker}],
        StartTime=_utc(now - 1800),
        EndTime=_utc(now + 120),
        Period=60,
        Statistics=["Sum"],
    )["Datapoints"]
    return sum(p["Sum"] for p in points)


def _utc(epoch: float):
    import datetime

    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)


def _assert_metric_datapoint(ctx, namespace: str, metric_name: str, worker: str, legs) -> str:
    """The worker's own put_metric_data lands as a queryable datapoint under the dimension the alarm
    keys on -- the join between the code path and the alarm."""
    deadline = 420.0
    started = time.monotonic()
    total = 0.0
    while time.monotonic() - started < deadline:
        total = _metric_sum(ctx, namespace, metric_name, worker)
        if total >= 1:
            return f"{namespace}/{metric_name} Sum={total}"
        time.sleep(2)
    legs.never_reached(
        f"custom metric {namespace}/{metric_name} for Worker={worker} never returned a datapoint",
        time.monotonic() - started,
    )
    return ""


def _alarm(ctx, name: str) -> dict:
    alarms = ctx.client("cloudwatch").describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert alarms, f"alarm {name} does not exist"
    return alarms[0]


def _assert_alarm_reaches_alarm(ctx, alarm_name: str, queue_url: str, legs) -> str:
    """The declared alarm evaluates the real datapoint and crosses into ALARM.

    Messages are re-sent while polling: one datapoint breaches for a single period, then settles OK.
    """
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")
    deadline = 480.0
    started = time.monotonic()
    last_send = 0.0
    state = None
    while time.monotonic() - started < deadline:
        if time.monotonic() - last_send > 30:
            sqs.send_message(QueueUrl=queue_url, MessageBody=_xname(ctx, "beat"))
            last_send = time.monotonic()
        state = _alarm(ctx, alarm_name)["StateValue"]
        if state == "ALARM":
            break
        time.sleep(2)
    if state != "ALARM":
        legs.never_reached(
            f"alarm {alarm_name} sat in {state!r} while the metric was breaching",
            time.monotonic() - started,
        )
    history = cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=100
    )["AlarmHistoryItems"]
    assert history, f"no StateUpdate history for {alarm_name}"
    transitions = []
    for item in history:
        try:
            data = json.loads(item["HistoryData"])
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
        transitions.append(
            (data.get("oldState", {}).get("stateValue"), data.get("newState", {}).get("stateValue"))
        )
    assert any(new == "ALARM" for _, new in transitions), (
        f"the alarm reports ALARM but records no transition into it: {transitions}"
    )
    # describe_alarm_history is newest-first, so the LAST item is the alarm's first ever transition.
    first_old = transitions[-1][0]
    assert first_old == "INSUFFICIENT_DATA", (
        f"the alarm's first transition came from {first_old!r}; a freshly created alarm starts in "
        f"INSUFFICIENT_DATA ({transitions})"
    )
    return f"INSUFFICIENT_DATA->ALARM via {len(transitions)} transition(s)"


def _wait_change_set(ctx, stack: str, cs_name: str, *, timeout_s=300.0) -> dict:
    cfn = ctx.client("cloudformation")
    return _poll_until(
        lambda: cfn.describe_change_set(StackName=stack, ChangeSetName=cs_name),
        lambda r: r["Status"] in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"change set {cs_name} on {stack}",
    )


def _assert_change_set_predicts(
    ctx, stack_name, params_v2, cfg_v1, cfg_v2, fn_name, queue_url, state
) -> str:
    """The change set predicts SSM Parameter replacement (create-only Name, Static) and an in-place
    Lambda modification, leaves untouched resources absent, and applies nothing.
    """
    cfn = ctx.client("cloudformation")
    cs_name = _xname(ctx, "cs")
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=(DEPLOYMENTS / _WORKER_TEMPLATE).read_text(),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params_v2.items()],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        ChangeSetType="UPDATE",
    )
    state["change_set"] = cs_name
    described = _wait_change_set(ctx, stack_name, cs_name)
    assert described["Status"] == "CREATE_COMPLETE", (
        f"change set {cs_name} ended {described['Status']!r}: {described.get('StatusReason')!r}"
    )
    assert described["ExecutionStatus"] == "AVAILABLE", described["ExecutionStatus"]

    changes = {}
    for change in described["Changes"]:
        assert change["Type"] == "Resource", change
        rc = change["ResourceChange"]
        changes[rc["LogicalResourceId"]] = rc
    state["predicted"] = changes

    cfg = changes.get("WorkerConfig")
    assert cfg, f"the change set does not mention WorkerConfig at all: {sorted(changes)}"
    assert cfg["Action"] == "Modify", cfg["Action"]
    assert cfg["Replacement"] == "True", (
        f"changing the create-only Name of an AWS::SSM::Parameter must predict Replacement=True, "
        f"got {cfg['Replacement']!r}"
    )
    assert "Properties" in cfg.get("Scope", []), f"Scope must name Properties: {cfg.get('Scope')!r}"
    name_details = [
        d
        for d in cfg.get("Details", [])
        if (d.get("Target") or {}).get("Name") == "Name"
    ]
    assert name_details, f"no per-property Detail for Name: {cfg.get('Details')!r}"
    assert any(d["Target"].get("RequiresRecreation") == "Always" for d in name_details), (
        f"Name must require recreation Always: {name_details!r}"
    )
    assert any(d.get("Evaluation") == "Static" for d in name_details), (
        f"a create-only property known from the template alone is a STATIC evaluation: {name_details!r}"
    )

    fn = changes.get("WorkerFunction")
    assert fn, f"the change set does not mention WorkerFunction: {sorted(changes)}"
    assert fn["Action"] == "Modify", fn["Action"]
    assert fn["Replacement"] == "False", (
        f"a Lambda environment-variable change is updatable in place; the change set predicted "
        f"Replacement={fn['Replacement']!r}"
    )
    recreations = {
        (d.get("Target") or {}).get("RequiresRecreation") for d in fn.get("Details", [])
    }
    assert recreations <= {"Never", None}, (
        f"no property of this function change requires recreation, change set says {recreations!r}"
    )

    role = changes.get("WorkerRole")
    assert role and role["Replacement"] == "False", (
        f"the role's inline policy embeds the parameter name, so it modifies in place: {role!r}"
    )

    for untouched in ("WorkQueue", "WorkerLogGroup", "ProcessedAlarm"):
        assert untouched not in changes, (
            f"{untouched} references no changed parameter and must not appear in the change set: "
            f"{changes.get(untouched)!r}"
        )

    # Nothing has been applied: a change set is a prediction until it is executed.
    ssm = ctx.client("ssm")
    assert ssm.get_parameter(Name=cfg_v1)["Parameter"]["Value"] == "tier-a", (
        "creating the change set already changed the live parameter"
    )
    _expect_error(
        lambda: ssm.get_parameter(Name=cfg_v2),
        (("ParameterNotFound",), _PARAMETER_NOT_FOUND_MESSAGE),
        "the replacement parameter must not exist before the change set is executed",
    )
    env = ctx.client("lambda").get_function_configuration(FunctionName=fn_name)["Environment"][
        "Variables"
    ]
    assert env["LOG_LEVEL"] == "INFO", f"creating the change set already updated the function: {env!r}"
    state["ids_before"] = _physical_ids(ctx, stack_name)
    state["queue_created_before"] = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["CreatedTimestamp"]
    )["Attributes"]["CreatedTimestamp"]
    return "predicted repl=WorkerConfig modify=WorkerFunction,WorkerRole untouched=queue,loggroup,alarm"


def _assert_reality_matches_prediction(
    ctx, stack_name, cfg_v1, cfg_v2, fn_name, queue_url, log_group, state
) -> str:
    """After execution the parameter is recreated and the old name gone, the function and queue keep
    their identity (queue CreatedTimestamp unchanged), and the worker reads the new configuration.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    cfn.execute_change_set(StackName=stack_name, ChangeSetName=state["change_set"])
    final = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in _UPDATE_TERMINAL,
        timeout_s=900.0,
        interval_s=2.0,
        description=f"execute change set on {stack_name}",
    )
    assert final == "UPDATE_COMPLETE", f"the update ended {final!r}"

    before = state["ids_before"]
    after = _physical_ids(ctx, stack_name)

    assert after["WorkerConfig"] == cfg_v2, after["WorkerConfig"]
    assert after["WorkerConfig"] != before["WorkerConfig"], (
        "Replacement=True was predicted but the parameter kept its physical id "
        f"{before['WorkerConfig']!r}"
    )
    _expect_error(
        lambda: ssm.get_parameter(Name=cfg_v1),
        (("ParameterNotFound",), _PARAMETER_NOT_FOUND_MESSAGE),
        "a replaced resource's OLD physical resource must be destroyed",
    )
    assert ssm.get_parameter(Name=cfg_v2)["Parameter"]["Value"] == "tier-b", (
        "the replacement parameter does not carry the new value"
    )

    for logical in ("WorkerFunction", "WorkQueue", "WorkerLogGroup", "ProcessedAlarm"):
        assert after[logical] == before[logical], (
            f"{logical} was predicted Replacement=False / untouched but its physical id changed: "
            f"{before[logical]!r} -> {after[logical]!r}"
        )
    created_after = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["CreatedTimestamp"]
    )["Attributes"]["CreatedTimestamp"]
    assert created_after == state["queue_created_before"], (
        f"the queue was recreated behind an unchanged URL: CreatedTimestamp "
        f"{state['queue_created_before']} -> {created_after}"
    )

    env = ctx.client("lambda").get_function_configuration(FunctionName=fn_name)["Environment"][
        "Variables"
    ]
    assert env["LOG_LEVEL"] == "DEBUG", env
    assert env["CONFIG_PARAM"] == cfg_v2, env

    marker = _xname(ctx, "msg2")
    ctx.client("sqs").send_message(QueueUrl=queue_url, MessageBody=marker)
    docs = _poll_until(
        lambda: [d for d in _json_lines(_log_messages(ctx, log_group)) if d.get("body") == marker],
        lambda ds: bool(ds),
        timeout_s=300.0,
        interval_s=2.0,
        description="worker log line after the update",
    )
    line = docs[0]
    assert line.get("level") == "DEBUG", line
    assert line.get("config") == "tier-b", (
        f"after the update the worker still reads {line.get('config')!r}; the replaced parameter "
        "holds 'tier-b'"
    )
    return f"replaced {cfg_v1}->{cfg_v2}, function id kept, delivery ok with tier-b"


def _resource_drifts(ctx, stack: str) -> list[dict]:
    cfn = ctx.client("cloudformation")
    out: list[dict] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kwargs)
        out.extend(page.get("StackResourceDrifts", []))
        token = page.get("NextToken")
        if not token:
            return out


def _detect_drift(ctx, stack: str, *, timeout_s=900.0) -> dict:
    cfn = ctx.client("cloudformation")
    detection_id = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    detection = _poll_until(
        lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id),
        lambda d: d["DetectionStatus"] != "DETECTION_IN_PROGRESS",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"drift detection for {stack}",
    )
    assert detection["DetectionStatus"] == "DETECTION_COMPLETE", (
        f"drift detection did not complete: {detection!r}"
    )
    return detection


def _assert_drift_reports_out_of_band_write(ctx, stack_name: str, cfg_name: str) -> str:
    """Drift reports the out-of-band SSM write MODIFIED, the queue IN_SYNC, and omits the event
    source mapping, which is not a drift-supported type.
    """
    ctx.client("ssm").put_parameter(Name=cfg_name, Value="drifted-out-of-band", Type="String", Overwrite=True)
    detection = _detect_drift(ctx, stack_name)
    drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(ctx, stack_name)}

    cfg = drifts.get("WorkerConfig")
    assert cfg, f"drift reported nothing for WorkerConfig: {sorted(drifts)}"
    assert cfg["StackResourceDriftStatus"] == "MODIFIED", (
        f"an out-of-band PutParameter must make the resource MODIFIED, got {cfg!r}"
    )
    diffs = cfg.get("PropertyDifferences") or []
    value_diffs = [d for d in diffs if d.get("PropertyPath", "").endswith("/Value")]
    assert value_diffs, f"no PropertyDifference for /Value: {diffs!r}"
    diff = value_diffs[0]
    assert diff["ExpectedValue"] == "tier-b", diff
    assert diff["ActualValue"] == "drifted-out-of-band", diff
    assert diff["DifferenceType"] == "NOT_EQUAL", diff

    queue = drifts.get("WorkQueue")
    assert queue and queue["StackResourceDriftStatus"] == "IN_SYNC", (
        f"the untouched queue must stay IN_SYNC, got {queue!r}"
    )
    esm = drifts.get("WorkerEsm")
    assert esm is None, (
        f"AWS::Lambda::EventSourceMapping does not support drift detection; CloudFormation must omit "
        f"it from describe_stack_resource_drifts entirely rather than reporting any status for it, "
        f"got {esm!r}"
    )
    assert detection["StackDriftStatus"] == "DRIFTED", detection
    stack_drift = ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0][
        "DriftInformation"
    ]
    assert stack_drift["StackDriftStatus"] == "DRIFTED", (
        f"DescribeStacks still reports {stack_drift!r} after a completed detection"
    )
    return "WorkerConfig MODIFIED /Value, WorkQueue IN_SYNC, WorkerEsm omitted"


def _assert_missing_config_permission_denies(ctx, namespace: str, metric_name: str) -> str:
    """With one role statement removed the message is still delivered but the work is denied: the IAM
    action is in the log, and no processed line, no datapoint and the message is not deleted.
    """
    fn_name = _xname(ctx, "denied")
    queue_name = _xname(ctx, "deniedq")
    cfg_name = _xname(ctx, "deniedcfg")
    log_group = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _swallow(lambda: ctx.client("ssm").delete_parameter(Name=cfg_name)))
    ctx.on_cleanup(
        lambda: _swallow(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))
    )
    stack = _deploy_cfn(
        ctx,
        (DEPLOYMENTS / _BROKEN_TEMPLATE).read_text(),
        parameters={
            "QueueName": queue_name,
            "FunctionName": fn_name,
            "WorkerConfigParamName": cfg_name,
            "WorkerConfigValue": "tier-denied",
            "MetricNamespace": namespace,
            "MetricName": metric_name,
        },
        timeout_s=600.0,
    )
    ctx.on_cleanup(lambda: _delete_stack_deadline(ctx, stack["stack_name"], timeout_s=900.0))
    queue_url = stack["outputs"]["QueueUrl"]

    marker = _xname(ctx, "deniedmsg")
    ctx.client("sqs").send_message(QueueUrl=queue_url, MessageBody=marker)
    denied = _poll_until(
        lambda: [
            m
            for m in _log_messages(ctx, log_group)
            if "GetParameter" in m and ("AccessDenied" in m or "not authorized" in m)
        ],
        lambda ms: bool(ms),
        timeout_s=420.0,
        interval_s=2.0,
        description=f"AccessDenied on ssm:GetParameter in {log_group}",
    )
    line = _one_line(denied[0], 200)

    processed = [d for d in _json_lines(_log_messages(ctx, log_group)) if d.get("event") == "work.processed"]
    assert not processed, (
        f"the role cannot read the config parameter, so no message may be reported processed: {processed!r}"
    )
    total = _metric_sum(ctx, namespace, metric_name, fn_name)
    assert total == 0, (
        f"the denied worker published {total} to {namespace}/{metric_name}; a handler that raised "
        "before put_metric_data cannot have emitted a datapoint"
    )
    # The ESM only deletes a message the handler returned successfully for, so the message must still
    # be accounted for by the queue (visible again, or in flight for another attempt).
    visible, in_flight = _poll_until(
        lambda: _queue_depth(ctx, queue_url),
        lambda d: (d[0] + d[1]) >= 1,
        timeout_s=180.0,
        interval_s=2.0,
        description=f"message still held by {queue_name} after the failed invocation",
    )
    return f"denied ({line[:60]}), no processed line, metric 0, queue holds {visible}/{in_flight}"


def _assert_teardown_stops_delivery(
    ctx, stack_name, queue_name, queue_url, fn_name, alarm_name, log_group
) -> str:
    """After delete_stack the resources are gone AND the wiring stops delivering: a send to the
    stack's queue URL is refused rather than silently accepted by a queue that outlived its stack."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    final = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=900.0,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )
    assert final in {"DELETE_COMPLETE", "GONE"}, f"stack delete ended {final!r}"

    _expect_error(
        lambda: ctx.client("sqs").get_queue_url(QueueName=queue_name),
        ((_NO_SUCH_QUEUE,), _NO_SUCH_QUEUE_MESSAGE),
        "the queue must be gone",
    )
    _expect_error(
        lambda: ctx.client("lambda").get_function(FunctionName=fn_name),
        (
            ("ResourceNotFoundException",),
            f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}",
        ),
        "the worker function must be gone",
    )
    assert not ctx.client("cloudwatch").describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"], (
        f"alarm {alarm_name} outlived its stack"
    )
    groups = [
        g["logGroupName"]
        for g in ctx.client("logs").describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
    ]
    assert log_group not in groups, f"log group {log_group} outlived its stack"

    code = _expect_error(
        lambda: ctx.client("sqs").send_message(QueueUrl=queue_url, MessageBody="after-teardown"),
        ((_NO_SUCH_QUEUE, "QueueDoesNotExist"), _NO_SUCH_QUEUE_MESSAGE),
        "the wiring must stop delivering after teardown",
    )
    return f"stack {final}, queue/function/alarm/log-group gone, send refused {code}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
