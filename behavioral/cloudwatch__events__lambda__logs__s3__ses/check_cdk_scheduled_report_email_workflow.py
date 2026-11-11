"""cdk-scheduled-report-email-workflow."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-scheduled-report-email-workflow"
GROUP = "deployment-order"
SERVICES = ["cloudwatch", "events", "lambda", "logs", "s3", "ses"]

_APP_DIR = Path(__file__).parent / "deployments" / "scheduled_report_cdk"
# The SES mailbox simulator: deliverable without verifying the recipient, which is what makes a send
# assertable in a sandbox account. The SENDER still has to be a verified identity, and verification
# needs an out-of-band inbox click or a DNS record -- see _verified_sender_email.
_SIMULATOR_RECIPIENT = "success@simulator.amazonses.com"


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "requires:dns-baseline", "timing:real-time")
def run(ctx) -> None:
    """A CDK-synthesized EventBridge rate rule -> Lambda -> S3 + SES report job, deployed through
    CloudFormation, runs on its own schedule with matching logs, metric, alarm and notification; an
    S3-denied variant writes nothing and sends nothing; a re-apply moves the prefix; the delete stops it."""
    sender = _verified_sender_email(ctx)
    sink = _create_queue(ctx, "sink")
    alerts = _create_queue(ctx, "alerts", allow_services=("sns.amazonaws.com",))
    probe_id = ctx.unique_name("probe-")
    base_context = {
        "sink_queue_url": sink["url"],
        "sink_queue_arn": sink["arn"],
        "alerts_queue_arn": alerts["arn"],
        "metric_namespace": _xname(ctx, "ns"),
        "probe_id": probe_id,
        "sender": sender,
        "recipient": _SIMULATOR_RECIPIENT,
    }
    happy_context = {
        **base_context,
        "variant": "ok",
        "bucket_name": _xname(ctx, "bkt"),
        "fn_name": _xname(ctx, "fn"),
        "rule_name": _xname(ctx, "rule"),
        "alarm_name": _xname(ctx, "alarm"),
        "report_prefix": "reports",
        "stage_label": "v1",
    }

    legs = _Legs(ctx, total=8)
    stack = legs.hard("deploy", lambda: _deploy(ctx, happy_context))
    legs.step("schedule", lambda: _assert_schedule_reports(ctx, stack, sink, legs))
    legs.step("logs", lambda: _assert_structured_log(ctx, stack, probe_id), requires=("schedule",))
    legs.step("metrics", lambda: _assert_metric_datapoint(ctx, stack, legs), requires=("schedule",))
    legs.step("alarm", lambda: _assert_alarm_notifies(ctx, stack, alerts, legs), requires=("metrics",))
    legs.step("denial", lambda: _assert_unpermitted_variant_writes_nothing(ctx, base_context), requires=("schedule",))
    legs.step("drift", lambda: _assert_second_apply_changes_prefix(ctx, stack, happy_context, sink), requires=("schedule",))
    legs.step("teardown", lambda: _assert_delete_stops_the_schedule(ctx, stack, sink), requires=("schedule",))
    legs.verdict()


# --- legs ---------------------------------------------------------------------------------------
def _deploy(ctx, context: dict[str, str]) -> dict[str, Any]:
    stack = _deploy_cdk(ctx, _APP_DIR, context=context)
    outputs = stack["outputs"]
    for key in ("BucketName", "FunctionName", "LogGroupName", "RuleName", "AlarmName", "MetricNamespace"):
        assert outputs.get(key), f"stack output {key} is absent: {sorted(outputs)}"
    # Registered AFTER the deploy so the LIFO cleanup order empties the bucket before the stack
    # delete: CloudFormation refuses to delete a non-empty bucket, and the construct that would empty
    # it is a file asset the asset-free deploy path rejects.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, outputs["BucketName"]))
    return stack


def _assert_schedule_reports(ctx, stack, sink, legs) -> str:
    """Nothing in this leg invokes the function: the rate rule is the only trigger, so a target that
    stores a schedule without running it produces no report at all."""
    out = stack["outputs"]
    report, seen = _await_event(
        ctx, sink["url"], "report_sent", timeout_s=420
    )
    if report is None:
        legs.never_reached(
            f"the rate(1 minute) rule {out['RuleName']} produced no report_sent "
            f"(events seen: {sorted({r.get('event') for r in seen})})",
            420,
        )
    assert report["reportKey"].startswith(out["ReportPrefix"] + "/"), report
    assert report["stageLabel"] == out["StageLabel"], report
    assert report["probeId"] == out["ProbeId"], report
    assert isinstance(report.get("sesMessageId"), str) and report["sesMessageId"], (
        f"SendEmail must return a message id the handler can report, got "
        f"{report.get('sesMessageId')!r}"
    )
    body = ctx.client("s3").get_object(Bucket=out["BucketName"], Key=report["reportKey"])["Body"].read()
    assert len(body) == report["bytes"], (
        f"the object at {report['reportKey']} is {len(body)} bytes, the run reported {report['bytes']}"
    )
    stored = json.loads(body.decode())
    assert stored["probeId"] == out["ProbeId"], stored
    assert stored["stageLabel"] == out["StageLabel"], stored
    return f"schedule wrote {report['reportKey']} and mailed {report['sesMessageId'][:24]}"


def _assert_structured_log(ctx, stack, probe_id: str) -> str:
    log_group = stack["outputs"]["LogGroupName"]
    message = _await_log_line(ctx, log_group, ('"event": "report_sent"', probe_id), timeout_s=300)
    parsed = json.loads(message.strip().splitlines()[-1])
    assert parsed["sesMessageId"], parsed
    streams = _log_group_streams(ctx, log_group)
    assert streams, f"{log_group} carried the line but reports no stream"
    return f"{log_group} stream {streams[0][:40]} carries report_sent"


def _assert_metric_datapoint(ctx, stack, legs) -> str:
    """The metric filter over the function's log group is the custom metric here: the datapoint is
    produced by CloudWatch Logs evaluating the pattern, not by a PutMetricData the handler made."""
    return _await_metric(
        ctx, stack["outputs"]["MetricNamespace"], "ReportsSent", [], timeout_s=480, legs=legs
    )


def _assert_alarm_notifies(ctx, stack, alerts, legs) -> str:
    """No feed: the schedule is its own datapoint source, which is the difference between this alarm
    and one an alarm-only check drives with SetAlarmState."""
    out = stack["outputs"]
    alarm = out["AlarmName"]
    transitions = _await_alarm_state(ctx, alarm, "ALARM", timeout_s=540, legs=legs)
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
    assert trigger.get("MetricName") == "ReportsSent", trigger
    return f"{transitions}; notified with Trigger on {out['MetricNamespace']}"


def _assert_unpermitted_variant_writes_nothing(ctx, base_context: dict[str, str]) -> str:
    """The failure-injection leg: the same schedule and handler with the bucket's put grant removed.

    The denial is the AccessDenied the handler caught on the operation it names; the effect-absent is
    an empty bucket AND the absence of any message id across every run in the window, which is what
    proves the send was never reached; the control is the happy stack's own schedule leg, which
    wrote and mailed through the identical wiring.

    The error MESSAGE is deliberately not asserted, only the code and the operation the handler was
    executing: S3 answers a denied PutObject with `AccessDenied` and does not guarantee that the
    message names the action, so asserting the text would make the leg fail on wording.
    """
    bad_sink = _create_queue(ctx, "badsink")
    broken = _deploy_cdk(
        ctx,
        _APP_DIR,
        context={
            **base_context,
            "variant": "deny_s3",
            "sink_queue_url": bad_sink["url"],
            "sink_queue_arn": bad_sink["arn"],
            "bucket_name": _xname(ctx, "bkt"),
            "fn_name": _xname(ctx, "fn"),
            "rule_name": _xname(ctx, "rule"),
            "alarm_name": _xname(ctx, "alarm"),
            "report_prefix": "reports",
            "stage_label": "denied",
        },
    )
    out = broken["outputs"]
    try:
        failed, seen = _await_event(ctx, bad_sink["url"], "report_failed", timeout_s=420)
        assert failed is not None, (
            f"the unpermitted schedule reported nothing in 420s; events seen: "
            f"{sorted({r.get('event') for r in seen})}"
        )
        assert failed["stage"] == "s3_put_failed", (
            f"the run must fail at the write it was refused, got stage={failed.get('stage')!r}"
        )
        assert failed["errorCode"] == "AccessDenied", (
            f"expected the S3 refusal code, got {failed.get('errorCode')!r}: "
            f"{_one_line(failed.get('detail'), 200)}"
        )
        assert not any(r.get("sesMessageId") for r in [*seen, failed]), (
            "a message id was issued although the run never got past the refused write"
        )
        listing = ctx.client("s3").list_objects_v2(Bucket=out["BucketName"])
        assert listing.get("KeyCount", 0) == 0, (
            f"{out['BucketName']} holds {listing.get('KeyCount')} object(s) after a refused PutObject"
        )
        _await_log_line(ctx, out["LogGroupName"], ('"stage": "s3_put_failed"',), timeout_s=180)
        return f"AccessDenied at s3_put_failed, {out['BucketName']} empty, no message id issued"
    finally:
        # Emptied and deleted in-band rather than left to ctx.run_cleanups: the cleanup budget is far
        # below a CloudFormation delete, so a failing assertion here would otherwise strand a stack
        # whose bucket blocks its own deletion. The bucket empty is tried first but the stack delete
        # always runs after it, even when emptying raised, so a real error there cannot skip the
        # delete and strand the whole stack.
        try:
            _empty_bucket(ctx, out.get("BucketName", ""))
        finally:
            _delete_stack_and_wait(ctx, broken["stack_name"])
            status = _stack_status(ctx, broken["stack_name"])
            assert status in {"DELETE_COMPLETE", "GONE"}, (
                f"the denial variant's stack {broken['stack_name']} ended {status} instead of "
                "deleting"
            )


def _assert_second_apply_changes_prefix(ctx, stack, happy_context: dict[str, str], sink) -> str:
    """The update/drift leg: a second apply changing the key prefix and the stamped label must MODIFY
    the function and the rule -- identical physical resource ids -- and the next scheduled run must
    write under the NEW prefix."""
    name = stack["stack_name"]
    before = _stack_resources(ctx, name)
    outputs = _update_cdk_stack(
        ctx,
        name,
        _APP_DIR,
        context={**happy_context, "report_prefix": "reports-v2", "stage_label": "v2"},
    )
    after = _stack_resources(ctx, name)
    replaced = []
    for resource_type in (
        "AWS::Lambda::Function",
        "AWS::Events::Rule",
        "AWS::S3::Bucket",
        "AWS::Logs::LogGroup",
    ):
        was = _physical_ids_of_type(before, resource_type)
        now = _physical_ids_of_type(after, resource_type)
        assert was, f"{resource_type} had no physical id before the second apply"
        if was != now:
            replaced.append(f"{resource_type}: {was} -> {now}")
    assert not replaced, f"the second apply REPLACED resources it should have modified: {replaced}"
    assert outputs["ReportPrefix"] == "reports-v2", outputs

    _drain(ctx, sink["url"])
    report, seen = _await_event(ctx, sink["url"], "report_sent", timeout_s=420, where=lambda r: r.get("stageLabel") == "v2")
    assert report is not None, (
        f"no run reported under the new configuration; events seen: "
        f"{sorted({(r.get('event'), r.get('stageLabel')) for r in seen})}"
    )
    assert report["reportKey"].startswith("reports-v2/"), report
    ctx.client("s3").head_object(Bucket=outputs["BucketName"], Key=report["reportKey"])
    return f"function/rule/bucket modified not replaced, next run wrote {report['reportKey']}"


def _assert_delete_stops_the_schedule(ctx, stack, sink) -> str:
    """Teardown correctness: after the delete the bucket, function, log group and rule are gone AND
    the schedule stops producing runs -- asserted as an absence at the out-of-stack sink over a window
    several rule periods long, not as a 404 from a describe."""
    out = _stack_outputs(ctx, stack["stack_name"])
    _empty_bucket(ctx, out["BucketName"])
    _delete_stack_and_wait(ctx, stack["stack_name"])
    _drain(ctx, sink["url"])

    assert _stack_status(ctx, stack["stack_name"]) in {"DELETE_COMPLETE", "GONE"}, (
        f"stack still reports {_stack_status(ctx, stack['stack_name'])}"
    )
    survivors = [
        label
        for label, present in (
            (f"bucket {out['BucketName']}", _bucket_exists(ctx, out["BucketName"])),
            (f"function {out['FunctionName']}", _function_exists(ctx, out["FunctionName"])),
            (f"rule {out['RuleName']}", _rule_exists(ctx, out["RuleName"])),
            (f"log group {out['LogGroupName']}", _log_group_exists(ctx, out["LogGroupName"])),
        )
        if present
    ]
    assert not survivors, f"these survived the stack delete: {survivors}"

    # Several rule periods of silence: one period would not distinguish "the schedule stopped" from
    # "the next tick has not come round yet".
    stragglers = _gather_reports(ctx, sink["url"], timeout_s=180)
    assert not stragglers, (
        f"the deleted schedule produced {len(stragglers)} further run(s): "
        f"{_one_line(json.dumps(stragglers[:1]), 200)}"
    )
    return "bucket/function/rule/log group gone, no further run over three rule periods"


# --- probes -------------------------------------------------------------------------------------
def _gather_reports(ctx, queue_url: str, *, timeout_s: float) -> list[dict[str, Any]]:
    """Every handler report the sink carried in the window, parsed."""
    reports = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body in _receive_bodies(ctx, queue_url, timeout_s=10.0):
            doc = _unwrap_sns(body)
            if doc is not None:
                reports.append(doc)
    return reports


def _await_event(ctx, queue_url: str, event: str, *, timeout_s: float, where=None):
    """Poll the sink for the first report whose `event` matches, returning (report, everything seen).

    Returns None for the report rather than raising, so the caller decides whether the absence is a
    convergence failure or a plain assertion.
    """
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body in _receive_bodies(ctx, queue_url, timeout_s=15.0):
            doc = _unwrap_sns(body)
            if doc is None:
                continue
            seen.append(doc)
            if doc.get("event") == event and (where is None or where(doc)):
                return doc, seen
    return None, seen


def _verified_sender_email(ctx) -> str:
    """An address under the target's verified sending domain (_sending_domain)."""
    domain = _sending_domain(ctx, ctx.client("route53"), ctx.client("sesv2"))
    return f"{ctx.unique_name('sim2real-ses-sender-')}@{domain}"


_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _sending_domain(ctx, route53, sesv2):
    """The target's DNS baseline domain (its tagged public hosted zone, verified in SES); an account without one fails the check."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified for sending in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag, verified in SES) and so no sending domain; the check requires one"
    )


def _empty_bucket(ctx, bucket: str) -> None:
    if not bucket:
        return
    s3 = ctx.client("s3")
    try:
        while True:
            page = s3.list_objects_v2(Bucket=bucket, MaxKeys=1000)
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if not keys:
                return
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"NoSuchBucket", "404"}:
            return
        raise


def _bucket_exists(ctx, bucket: str) -> bool:
    try:
        ctx.client("s3").head_bucket(Bucket=bucket)
    except ClientError:
        return False
    return True


def _rule_exists(ctx, rule_name: str) -> bool:
    try:
        ctx.client("events").describe_rule(Name=rule_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"ResourceNotFoundException", "NotFoundException"}:
            return False
        raise
    return True


def _function_exists(ctx, fn_name: str) -> bool:
    try:
        ctx.client("lambda").get_function(FunctionName=fn_name)
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
    """Collapse to a single line. Load-bearing: a leg's evidence must not be able to introduce a
    newline, or IT becomes the last line of the detail and displaces the summary."""
    flat = " ".join(str(text).split())
    return flat[:cap]


class _Legs:
    """One PASS / FAIL / BLOCKED verdict per workflow leg, raised ONCE at the end.

    The summary is the LAST line of the message on purpose, so a report that keeps only the last
    line of a failure still names the failing leg.
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

        BLOCKED rather than FAIL is load-bearing: one broken hop would otherwise show up as a
        failure in every downstream leg.
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
        # The cells are truncated, NEVER the headline: the headline is the last line, so it must
        # survive intact.
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


# --- naming + tagging: every resource the check creates carries this prefix and tag, so none is
# --- left unattributable.
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
    """The FAILED stack events' own words, one line. Without this a rollback reports only its
    status, which names no resource and no cause."""
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
    """Every resource in the stack, with its type and PHYSICAL id.

    The physical id is the only thing that answers the update/drift leg's question: an identical id
    across two applies means CloudFormation MODIFIED the resource in place, a changed one means it
    REPLACED it. A property read cannot tell those apart. Selection is by RESOURCE TYPE rather than
    by logical id because CDK suffixes logical ids with a construct hash and several constructs in
    one stack share a logical-id prefix.
    """
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


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=900.0, raise_on_leak: bool = False) -> None:
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
    if status == "DELETE_FAILED" and raise_on_leak:
        # From teardown it raises; from the graded legs, the leg's own asserts grade the outcome.
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, raise_on_leak=True))
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
    """`cdk synth` the app into a bootstrap-free CloudFormation body.

    Split out of _deploy_cdk so the update/drift leg can re-synth the SAME app under different
    context values and hand the result to update_stack — a second create_stack would answer
    nothing about modify-vs-replace.
    """
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
    """An out-of-stack SQS queue the deployed app reports into.

    Out of stack on purpose: the teardown leg has to observe that delivery STOPPED, and a sink
    deleted along with the stack cannot witness its own silence.
    """
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
    """Discard whatever is already queued, so a later absence assertion is about the window it
    covers and not about a message from an earlier leg."""
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
    """The first log event in *log_group* containing every needle.

    FilterLogEvents rather than a stream read: a Lambda's stream name is chosen by the service and
    is not derivable from the stack, so the group plus the payload is the only stable handle.
    """
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
    """A custom metric datapoint the deployed app published. Convergence failure is reported
    through legs.never_reached: metric ingestion latency on real AWS is not a fidelity finding."""
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
    """Drive the alarm to *want* and return its StateReason.

    `feed` is re-invoked on every poll iteration so each CloudWatch evaluation cycle sees fresh
    data rather than racing one stale datapoint.
    """
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
