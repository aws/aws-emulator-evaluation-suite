"""cfn-search-indexing-pipeline-alarm-config-workflow."""

from __future__ import annotations

import datetime
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-search-indexing-pipeline-alarm-config-workflow"

GROUP = "deployment-order"

SERVICES = ["cloudwatch", "iam", "lambda", "logs", "opensearch", "s3"]

DEPLOYMENTS = Path(__file__).parent / "deployments"

_DOMAIN_TEMPLATE = "search-domain.yaml"
_PIPELINE_TEMPLATE = "search-pipeline.yaml"
_BROKEN_TEMPLATE = "search-pipeline-readonly-role.yaml"


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation S3 -> Lambda -> OpenSearch pipeline indexes an object a signed GET and
    _search find, its one-minute alarm reports its deployed configuration, a role without
    es:ESHttpPut indexes nothing, and teardown stops delivery.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    legs = _Legs(ctx, total=11)

    # OpenSearch domain names are 3-28 chars, so the usual `<prefix>-<kind>-<uuid>` does not fit. The
    # `sim2real-xsvc-` prefix is kept; the `kind` segment is what gives way.
    domain_name = ("sim2real-xsvc-" + ctx.unique_name(""))[:28].rstrip("-")
    bucket_name = _xname(ctx, "docs")
    fn_name = _xname(ctx, "indexer")
    log_group = f"/aws/lambda/{fn_name}"
    namespace = "SimParity/SearchPipeline"
    metric_name = "DocumentsIndexed" + ctx.unique_name("")[:10]
    index_v1 = "orders-v1"
    index_v2 = "orders-v2"

    domain = legs.hard(
        "domain",
        lambda: _deploy_cfn(
            ctx,
            (DEPLOYMENTS / _DOMAIN_TEMPLATE).read_text(),
            parameters={"DomainName": domain_name, "EngineVersion": "OpenSearch_2.11"},
            timeout_s=2400.0,
        ),
    )
    ctx.on_cleanup(
        lambda: _delete_stack_deadline(ctx, domain["stack_name"], timeout_s=1800.0)
    )
    endpoint = domain["outputs"]["DomainEndpoint"]
    domain_arn = domain["outputs"]["DomainArn"]

    ctx.on_cleanup(
        lambda: _swallow(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))
    )

    params = {
        "BucketName": bucket_name,
        "FunctionName": fn_name,
        "DomainEndpoint": endpoint,
        "DomainArn": domain_arn,
        "IndexName": index_v1,
        "MetricNamespace": namespace,
        "MetricName": metric_name,
    }
    stack = legs.hard(
        "deploy",
        lambda: _deploy_cfn(
            ctx, (DEPLOYMENTS / _PIPELINE_TEMPLATE).read_text(), parameters=params, timeout_s=900.0
        ),
    )
    stack_name = stack["stack_name"]
    ctx.on_cleanup(lambda: _delete_stack_deadline(ctx, stack_name, timeout_s=900.0))
    # Registered AFTER the stack deleter so LIFO empties the bucket FIRST: CloudFormation refuses to
    # delete a non-empty bucket and the whole stack delete would fail on it.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    state: dict[str, Any] = {}

    legs.step("wiring", lambda: _assert_object_is_indexed(ctx, bucket_name, endpoint, index_v1, state))
    legs.step("search", lambda: _assert_document_is_queryable(ctx, endpoint, index_v1, state), requires=("wiring",))
    legs.step("logs", lambda: _assert_structured_line(ctx, log_group, state), requires=("wiring",))
    legs.step(
        "metrics",
        lambda: _assert_metric_filter_datapoint(ctx, namespace, metric_name, legs),
        requires=("logs",),
    )
    legs.step(
        "alarm",
        lambda: _assert_alarm_configuration(
            ctx, stack["outputs"]["AlarmName"], namespace, metric_name
        ),
    )
    legs.step(
        "update",
        lambda: _assert_reindex_target_modifies_in_place(
            ctx, stack_name, params, bucket_name, fn_name, endpoint, index_v1, index_v2, state
        ),
        requires=("wiring",),
    )
    legs.step("drift", lambda: _assert_drift_reports_retention_write(ctx, stack_name, log_group), requires=("update",))
    legs.step(
        "denial",
        lambda: _assert_readonly_role_indexes_nothing(ctx, endpoint, domain_arn),
    )
    legs.step(
        "teardown",
        lambda: _assert_teardown_stops_delivery(ctx, stack_name, bucket_name, fn_name, log_group),
    )
    # The domain delete outlasts the teardown budget, so it runs inside the check's own budget; the
    # registered cleanup stays as the backstop and returns at once when the stack is gone.
    try:
        _delete_stack_deadline(ctx, domain["stack_name"], timeout_s=1800.0)
    finally:
        legs.verdict()


_EVIDENCE_CAP = 120
_HEADLINE_CAP = 280


def _one_line(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Collapse to a single line, so a leg's evidence cannot displace the summary's last line."""
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
        #: prerequisite was BLOCKED is blocked too, transitively.
        self._not_passed: set[str] = set()

    def _record(self, name: str, verdict: str, evidence: str) -> None:
        self._rows.append((name, verdict, evidence))
        # Printed as it happens so a green run still says which legs it actually proved, and so a
        # run killed by the budget leaves a trail the summary never got to emit.
        print(f"[leg {len(self._rows)}/{self._total}] {verdict:7} {name}: {evidence}", flush=True)

    def step(self, name: str, fn, *, requires: tuple[str, ...] = ()):
        """Run leg *name*; record BLOCKED when a prerequisite did not pass.

        BLOCKED rather than FAIL keeps one broken hop from counting as a failure per downstream leg.
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
        # The cells are truncated, never the headline, which must survive intact as the last line.
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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
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
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
        return "GONE"


def _delete_stack_deadline(ctx, name: str, *, timeout_s: float) -> None:
    """delete_stack with a long wait: an OpenSearch domain takes many minutes to delete.

    Returns once the stack is gone; a failed or unfinished delete raises."""
    cfn = ctx.client("cloudformation")
    if _stack_status(cfn, name) == "GONE":
        return
    cfn.delete_stack(StackName=name)
    final = _poll_until(
        lambda: _stack_status(cfn, name),
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"delete stack {name}",
    )
    if final == "DELETE_FAILED":
        raise RuntimeError(f"stack {name} ended DELETE_FAILED — its resources are stranded")


def _empty_bucket(ctx, bucket: str) -> None:
    """Delete every object (and version) in the bucket. CloudFormation refuses to delete a non-empty
    bucket, so without this the whole stack delete fails and every resource in it is stranded."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
    except ClientError as exc:
        if _error_code(exc) != "NoSuchBucket":
            raise RuntimeError(f"emptying {bucket} failed: {exc}") from exc


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _refusal(fn, what: str) -> tuple[str, str]:
    """The (code, message) of the ClientError fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        return _error_code(exc), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"{what}: the call SUCCEEDED; expected a refusal")


def _utc(epoch: float):
    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)


def _os_request(ctx, endpoint: str, method: str, path: str, body: Any = None) -> tuple[int, Any]:
    """A SigV4-signed request to the domain's HTTP data plane with the check's own credentials.

    The indexer's report of success is not evidence, and DescribeDomain cannot see documents.
    """
    creds = ctx.client("opensearch")._request_signer._credentials
    if hasattr(creds, "get_frozen_credentials"):
        creds = creds.get_frozen_credentials()
    url = f"{ctx.endpoint_url(endpoint)}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(creds, "es", ctx.region).add_auth(req)
    http = urllib.request.Request(url, data=req.body, headers=dict(req.headers), method=method)
    try:
        with urllib.request.urlopen(http, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except (json.JSONDecodeError, ValueError):
            parsed = {"raw": raw.decode("utf-8", "replace")}
        return exc.code, parsed
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
        return 0, {"transport": f"{type(exc).__name__}: {exc}"}


def _log_messages(ctx, group: str) -> list[str]:
    """Every log message in the group, across streams (filter_log_events, matched in Python)."""
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
        interval_s=10.0,
        description=f"drift detection for {stack}",
    )
    assert detection["DetectionStatus"] == "DETECTION_COMPLETE", (
        f"drift detection did not complete: {detection!r}"
    )
    return detection


def _put_document(ctx, bucket: str, key: str, payload: dict) -> None:
    ctx.client("s3").put_object(
        Bucket=bucket, Key=key, Body=json.dumps(payload).encode(), ContentType="application/json"
    )


# ---- legs ----------------------------------------------------------------------------------------


def _assert_object_is_indexed(ctx, bucket: str, endpoint: str, index: str, state) -> str:
    """The notification the template configured fires, the indexer writes, and the document is
    readable from the domain's HTTP data plane -- read by the check, not reported by the indexer."""
    key = f"docs/{_xname(ctx, 'doc')}.json"
    title = _xname(ctx, "title")
    state["key_v1"] = key
    state["title_v1"] = title
    _put_document(ctx, bucket, key, {"title": title, "body": "the quick brown fox indexes documents"})
    # The domain decodes the %2F path segment back to a literal slash before assigning the document
    # id, so the real _id OpenSearch reports is the raw key -- the percent-encoded form below is only
    # a path component to address it, never the identifier a search hit or a GET body will echo back.
    doc_id = urllib.parse.quote(key, safe="")
    state["doc_id_v1"] = doc_id
    status, doc = _poll_until(
        lambda: _os_request(ctx, endpoint, "GET", f"/{index}/_doc/{doc_id}"),
        lambda r: r[0] == 200,
        timeout_s=420.0,
        interval_s=10.0,
        description=f"document {key} present in {index}",
    )
    assert status == 200, (status, doc)
    assert doc.get("_id") == key, (
        f"the domain must decode the %2F path segment back to a literal slash: expected _id "
        f"{key!r}, got {doc.get('_id')!r}"
    )
    source = doc["_source"]
    assert source["key"] == key, source
    assert source["title"] == title, source
    assert source["bucket"] == bucket, source
    assert source["size"] > 0, source
    return f"indexed {key} into {index}"


def _assert_document_is_queryable(ctx, endpoint: str, index: str, state) -> str:
    """Stored is not the same as SEARCHABLE: a match query against the analysed body has to return the
    document as a hit, which is the part of OpenSearch no control-plane read can stand in for."""
    body = {"query": {"match": {"body": "indexes"}}, "size": 5}
    status, result = _poll_until(
        lambda: _os_request(ctx, endpoint, "POST", f"/{index}/_search", body),
        lambda r: r[0] == 200 and (r[1].get("hits") or {}).get("hits"),
        timeout_s=300.0,
        interval_s=10.0,
        description=f"match query on {index} returns a hit",
    )
    assert status == 200, (status, result)
    hits = result["hits"]["hits"]
    ids = [h["_id"] for h in hits]
    # The hit's _id is the raw key (see the comment in _assert_object_is_indexed): the domain decodes
    # the %2F path segment it was written through, so `key_v1`, not the percent-encoded `doc_id_v1`,
    # is what a search hit actually echoes back.
    assert state["key_v1"] in ids, (
        f"the match query returned {ids}, which does not include the indexed document"
    )
    hit = next(h for h in hits if h["_id"] == state["key_v1"])
    assert hit["_source"]["title"] == state["title_v1"], hit
    assert hit.get("_score", 0) > 0, f"a matched hit must carry a score: {hit!r}"
    return f"search returned {len(hits)} hit(s), score {hit['_score']:.3f}"


def _assert_structured_line(ctx, log_group: str, state) -> str:
    """The DECLARED log group holds the indexer's structured line with the status OpenSearch returned,
    and the retention the template asked for."""
    groups = ctx.client("logs").describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
    declared = [g for g in groups if g["logGroupName"] == log_group]
    assert declared, f"the template's AWS::Logs::LogGroup {log_group} does not exist"
    assert declared[0].get("retentionInDays") == 7, declared[0]
    docs = _poll_until(
        lambda: [
            d
            for d in _json_lines(_log_messages(ctx, log_group))
            if d.get("event") == "document.indexed" and d.get("key") == state["key_v1"]
        ],
        lambda ds: bool(ds),
        timeout_s=240.0,
        interval_s=10.0,
        description=f"document.indexed line for {state['key_v1']}",
    )
    line = docs[0]
    assert line.get("status") in (200, 201), line
    assert line.get("requestId"), line
    return f"document.indexed status={line['status']}"


def _assert_metric_filter_datapoint(ctx, namespace, metric_name, legs) -> str:
    """The AWS::Logs::MetricFilter turns the structured line into a real datapoint."""
    started = time.monotonic()
    deadline = 420.0
    total = 0.0
    while time.monotonic() - started < deadline:
        now = time.time()
        points = ctx.client("cloudwatch").get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=_utc(now - 1800),
            EndTime=_utc(now + 120),
            Period=60,
            Statistics=["Sum"],
        )["Datapoints"]
        total = sum(p["Sum"] for p in points)
        if total >= 1:
            return f"{namespace}/{metric_name} Sum={total}"
        time.sleep(2)
    legs.never_reached(
        f"metric filter never produced a datapoint for {namespace}/{metric_name}",
        time.monotonic() - started,
    )
    return ""


def _assert_alarm_configuration(ctx, alarm_name: str, namespace: str, metric_name: str) -> str:
    """The declared alarm reports the metric-filter metric, one-minute period, statistic,
    threshold, comparison and missing-data treatment it is deployed with, and no enabled actions."""
    rows = ctx.client("cloudwatch").describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert [r["AlarmName"] for r in rows] == [alarm_name], (
        f"DescribeAlarms for {alarm_name} returned {rows!r}"
    )
    got = rows[0]
    shape = (
        got["Namespace"],
        got["MetricName"],
        got.get("Dimensions", []),
        got["Statistic"],
        got["Period"],
        got["EvaluationPeriods"],
        got["Threshold"],
        got["ComparisonOperator"],
        got["TreatMissingData"],
        got["ActionsEnabled"],
    )
    want = (
        namespace, metric_name, [], "Sum", 60, 1, 0.0, "GreaterThanThreshold", "missing", False,
    )
    assert shape == want, f"alarm {alarm_name} reads {shape}, deployed as {want}"
    return f"{alarm_name} reports Period=60 on {metric_name} as deployed"


def _assert_reindex_target_modifies_in_place(
    ctx, stack_name, params, bucket, fn_name, endpoint, index_v1, index_v2, state
) -> str:
    """A second apply re-points the indexer at a new index, modifying the function in place: a new
    object lands in the new index while the earlier document stays in the old one."""
    cfn = ctx.client("cloudformation")
    before = _physical_ids(ctx, stack_name)
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=(DEPLOYMENTS / _PIPELINE_TEMPLATE).read_text(),
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v}
            for k, v in dict(params, IndexName=index_v2).items()
        ],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    final = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in _UPDATE_TERMINAL,
        timeout_s=900.0,
        interval_s=10.0,
        description=f"update stack {stack_name}",
    )
    assert final == "UPDATE_COMPLETE", f"the update ended {final!r}"
    after = _physical_ids(ctx, stack_name)
    for logical in ("IndexerFunction", "DocumentBucket", "IndexerRole", "IndexerLogGroup"):
        assert after[logical] == before[logical], (
            f"{logical} was replaced by an in-place property change: {before[logical]!r} -> "
            f"{after[logical]!r}"
        )
    env = ctx.client("lambda").get_function_configuration(FunctionName=fn_name)["Environment"][
        "Variables"
    ]
    assert env["OS_INDEX"] == index_v2, env

    key = f"docs/{_xname(ctx, 'doc2')}.json"
    _put_document(ctx, bucket, key, {"title": "after-update", "body": "reindexed after the update"})
    doc_id = urllib.parse.quote(key, safe="")
    status, _doc = _poll_until(
        lambda: _os_request(ctx, endpoint, "GET", f"/{index_v2}/_doc/{doc_id}"),
        lambda r: r[0] == 200,
        timeout_s=420.0,
        interval_s=10.0,
        description=f"document {key} present in {index_v2} after the update",
    )
    assert status == 200, status
    old_status, old_doc = _os_request(ctx, endpoint, "GET", f"/{index_v1}/_doc/{state['doc_id_v1']}")
    assert old_status == 200, (
        f"the document indexed before the update is no longer in {index_v1}: {old_status} {old_doc!r}"
    )
    return f"function modified in place, new object -> {index_v2}, {index_v1} intact"


def _assert_drift_reports_retention_write(ctx, stack_name: str, log_group: str) -> str:
    """The retention is written through CloudWatch Logs, never through CloudFormation. The bucket is
    the barrier: a target that drifts a whole stack when one resource changes reports DRIFTED here
    too."""
    ctx.client("logs").put_retention_policy(logGroupName=log_group, retentionInDays=30)
    detection = _detect_drift(ctx, stack_name)
    drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(ctx, stack_name)}

    group = drifts.get("IndexerLogGroup")
    assert group, f"drift reported nothing for IndexerLogGroup: {sorted(drifts)}"
    assert group["StackResourceDriftStatus"] == "MODIFIED", (
        f"an out-of-band PutRetentionPolicy must make the log group MODIFIED, got {group!r}"
    )
    diffs = [
        d
        for d in (group.get("PropertyDifferences") or [])
        if d.get("PropertyPath", "").endswith("/RetentionInDays")
    ]
    assert diffs, f"no PropertyDifference for /RetentionInDays: {group.get('PropertyDifferences')!r}"
    assert str(diffs[0]["ExpectedValue"]) == "7", diffs[0]
    assert str(diffs[0]["ActualValue"]) == "30", diffs[0]

    bucket = drifts.get("DocumentBucket")
    assert bucket and bucket["StackResourceDriftStatus"] == "IN_SYNC", (
        f"the untouched bucket must stay IN_SYNC, got {bucket!r}"
    )
    assert detection["StackDriftStatus"] == "DRIFTED", detection
    return "IndexerLogGroup MODIFIED /RetentionInDays 7->30, DocumentBucket IN_SYNC"


def _assert_readonly_role_indexes_nothing(ctx, endpoint: str, domain_arn: str) -> str:
    """Without es:ESHttpPut the indexer logs a 403 naming that action, a signed GET returns 404 for
    the document, and no `document.indexed` line appears.
    """
    bucket = _xname(ctx, "denydocs")
    fn_name = _xname(ctx, "denyindexer")
    log_group = f"/aws/lambda/{fn_name}"
    index = "orders-denied"
    ctx.on_cleanup(
        lambda: _swallow(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))
    )
    stack = _deploy_cfn(
        ctx,
        (DEPLOYMENTS / _BROKEN_TEMPLATE).read_text(),
        parameters={
            "BucketName": bucket,
            "FunctionName": fn_name,
            "DomainEndpoint": endpoint,
            "DomainArn": domain_arn,
            "IndexName": index,
        },
        timeout_s=900.0,
    )
    ctx.on_cleanup(
        lambda: _delete_stack_deadline(ctx, stack["stack_name"], timeout_s=900.0)
    )
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    key = f"docs/{_xname(ctx, 'denydoc')}.json"
    _put_document(ctx, bucket, key, {"title": "denied", "body": "must never be indexed"})
    doc_id = urllib.parse.quote(key, safe="")
    rejected = _poll_until(
        lambda: [
            d
            for d in _json_lines(_log_messages(ctx, log_group))
            if d.get("event") == "document.rejected" and d.get("key") == key
        ],
        lambda ds: bool(ds),
        timeout_s=420.0,
        interval_s=10.0,
        description=f"document.rejected line for {key}",
    )
    line = rejected[0]
    assert line["status"] == 403, (
        f"a role without es:ESHttpPut must be refused with 403, the domain answered {line['status']}"
    )
    detail = line.get("detail", "")
    assert "es:ESHttpPut" in detail, (
        f"the refusal must name the action that was denied: {_one_line(detail, 200)}"
    )

    indexed = [
        d for d in _json_lines(_log_messages(ctx, log_group)) if d.get("event") == "document.indexed"
    ]
    assert not indexed, f"the denied indexer reported a write it did not make: {indexed!r}"
    status, body = _os_request(ctx, endpoint, "GET", f"/{index}/_doc/{doc_id}")
    error = body.get("error") if isinstance(body, dict) else None
    got = (status, *((error.get("type"), error.get("reason")) if isinstance(error, dict) else (None, None)))
    # The refused write never created the index, so the GET names the missing index.
    want = (404, "index_not_found_exception", f"no such index [{index}]")
    assert got == want, (
        f"the write was refused and the domain answered {got} ({_one_line(json.dumps(body), 200)}), "
        f"expected {want}"
    )
    return f"403 naming es:ESHttpPut, GET /{index}/_doc -> 404, no indexed line"


def _assert_teardown_stops_delivery(ctx, stack_name, bucket, fn_name, log_group) -> str:
    """After delete_stack the resources are gone AND the wiring stops delivering: an upload to the
    recorded bucket name is refused rather than silently accepted by a bucket that outlived its
    stack."""
    cfn = ctx.client("cloudformation")
    # The bucket has to be emptied first: CloudFormation refuses to delete a non-empty bucket and the
    # stack would end DELETE_FAILED with every resource stranded.
    _empty_bucket(ctx, bucket)
    cfn.delete_stack(StackName=stack_name)
    final = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=900.0,
        interval_s=10.0,
        description=f"delete stack {stack_name}",
    )
    assert final in {"DELETE_COMPLETE", "GONE"}, f"stack delete ended {final!r}"

    got = _refusal(lambda: ctx.client("s3").head_bucket(Bucket=bucket), "the document bucket must be gone")
    assert got == ("404", "Not Found"), f"the document bucket must be gone: got {got!r}"
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    got = _refusal(
        lambda: ctx.client("lambda").get_function(FunctionName=fn_name), "the indexer function must be gone"
    )
    assert got == (
        "ResourceNotFoundException",
        f"Function not found: arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:{fn_name}",
    ), f"the indexer function must be gone: got {got!r}"
    groups = [
        g["logGroupName"]
        for g in ctx.client("logs").describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
    ]
    assert log_group not in groups, f"log group {log_group} outlived its stack"

    code, message = _refusal(
        lambda: ctx.client("s3").put_object(Bucket=bucket, Key="after/teardown.json", Body=b"{}"),
        "the wiring must stop delivering after teardown",
    )
    assert (code, message) == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"the wiring must stop delivering after teardown: got {(code, message)!r}"
    )
    return f"stack {final}, bucket/function/log-group gone, upload refused {code}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
