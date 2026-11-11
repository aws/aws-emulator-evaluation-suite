"""obs-opensearch-3-index-slow-and-application-logs-publish-to-their-own-log-groups."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "obs-opensearch-3-index-slow-and-application-logs-publish-to-their-own-log-groups"
GROUP = "e2e"
SERVICES = ["logs", "opensearch"]

# Cheapest legal single-node topology.
_ENGINE_VERSION = "OpenSearch_2.11"
_MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
_MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# "0ms" makes every index operation exceed the warn threshold, so every write is logged.
_THRESHOLD_KEY = "index.indexing.slowlog.threshold.index.warn"
_THRESHOLD_LOGGED = "0ms"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """INDEX_SLOW_LOGS and ES_APPLICATION_LOGS, enabled by one UpdateDomainConfig, each publish to
    their own log group: only the 0ms-threshold index logs a write, the slow-log line stays out of
    the application group, and a nonexistent log group is rejected with ValidationException.
    """
    logs = ctx.client("logs")
    osc = ctx.client("opensearch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # --- 1. Prerequisites, created in-check: two log groups (one per LogType), each with its own
    # RESOURCE-scoped policy letting es.amazonaws.com write into it. The domain name is fixed HERE
    # so each policy's confused-deputy condition can name the domain before it exists.
    domain_name = ctx.unique_name("sim2real-osidx-")  # 15 + 12 hex = 27 <= 28
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{domain_name}"
    index_group = ctx.unique_name("sim2real-behav-osidx-index-")
    app_group = ctx.unique_name("sim2real-behav-osidx-app-")
    index_group_arn = _log_group_with_es_policy(ctx, logs, index_group, account, domain_arn)
    app_group_arn = _log_group_with_es_policy(ctx, logs, app_group, account, domain_arn)
    assert index_group_arn != app_group_arn, (
        f"expected two distinct log group ARNs, got {index_group_arn!r} twice"
    )

    # --- 2. The domain, created with NO log publishing: only a genuine disabled->enabled
    # UpdateDomainConfig transition delivers.
    _create_domain(ctx, osc, domain_name)
    _wait_settled(osc, domain_name, timeout_s=1500.0)

    # --- 3. Negative, against the now-Active domain: a log group ARN in this account and region
    # that names a group nobody created. It must be refused, synchronously, with ValidationException.
    missing_group = ctx.unique_name("sim2real-behav-osidx-missing-")
    missing_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{missing_group}"
    missing_listed = logs.describe_log_groups(logGroupNamePrefix=missing_group)["logGroups"]
    assert missing_listed == [], (
        f"expected no log group named {missing_group!r} to exist before the negative probe, got "
        f"{missing_listed!r}"
    )
    rejected = _update_log_publishing(
        osc,
        domain_name,
        {"INDEX_SLOW_LOGS": {"CloudWatchLogsLogGroupArn": missing_arn, "Enabled": True}},
    )
    assert rejected is not None, (
        f"expected UpdateDomainConfig naming the nonexistent log group {missing_arn} to be "
        f"REJECTED, but it was accepted"
    )
    assert rejected[0] == "ValidationException", (
        f"expected UpdateDomainConfig naming the nonexistent log group {missing_arn} to fail with "
        f"ValidationException, got {rejected[0]!r}: {rejected[1]!r}"
    )
    after_reject = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
    leaked = {
        k: v
        for k, v in (after_reject.get("LogPublishingOptions") or {}).items()
        if v.get("CloudWatchLogsLogGroupArn") == missing_arn or v.get("Enabled") is True
    }
    assert not leaked, (
        f"expected the rejected UpdateDomainConfig to leave NO enabled publishing option and no "
        f"trace of {missing_arn} on {domain_name}, got {leaked!r}"
    )

    # --- 4. Positive control on the same domain: the identical call shape with the two real,
    # granted groups is accepted, and the domain converges.
    accepted = _update_log_publishing(
        osc,
        domain_name,
        {
            "INDEX_SLOW_LOGS": {"CloudWatchLogsLogGroupArn": index_group_arn, "Enabled": True},
            "ES_APPLICATION_LOGS": {"CloudWatchLogsLogGroupArn": app_group_arn, "Enabled": True},
        },
    )
    assert accepted is None, (
        f"expected UpdateDomainConfig enabling INDEX_SLOW_LOGS -> {index_group_arn} and "
        f"ES_APPLICATION_LOGS -> {app_group_arn} to be accepted, got {accepted!r}"
    )
    # AWS documents enabling log publishing as typically taking about 30 minutes.
    endpoint = _wait_settled(osc, domain_name, timeout_s=2400.0)
    base = ctx.endpoint_url(endpoint)

    # --- 5. DescribeDomain echoes each group ARN back under its own LogType, and nothing else.
    published = osc.describe_domain(DomainName=domain_name)["DomainStatus"]["LogPublishingOptions"]
    for log_type, want_arn in (
        ("INDEX_SLOW_LOGS", index_group_arn),
        ("ES_APPLICATION_LOGS", app_group_arn),
    ):
        got = published.get(log_type)
        assert got is not None, (
            f"expected DescribeDomain LogPublishingOptions to carry {log_type}, got {published!r}"
        )
        assert got.get("Enabled") is True, (
            f"expected {log_type} Enabled=True on {domain_name}, got {got!r}"
        )
        assert got.get("CloudWatchLogsLogGroupArn") == want_arn, (
            f"expected {log_type} to echo back the log group this check created ({want_arn}), "
            f"got {got.get('CloudWatchLogsLogGroupArn')!r}"
        )
    enabled_types = sorted(k for k, v in published.items() if v.get("Enabled") is True)
    assert enabled_types == ["ES_APPLICATION_LOGS", "INDEX_SLOW_LOGS"], (
        f"expected exactly INDEX_SLOW_LOGS and ES_APPLICATION_LOGS enabled, got {enabled_types!r} "
        f"from {published!r}"
    )
    assert missing_arn not in json.dumps(published), (
        f"expected the rejected ARN {missing_arn} to appear nowhere in the publishing options, "
        f"got {published!r}"
    )

    # --- 6. Two indices on the SAME domain: one with the indexing warn threshold at 0ms, its twin
    # left UNTOUCHED (no slowlog setting at all, so the default -1 applies).
    index_logged = "sim2real-osidx-logged"
    index_quiet = "sim2real-osidx-quiet"
    _wait_data_plane_ready(ctx, base, timeout_s=180.0)
    for index in (index_logged, index_quiet):
        status_code, body = _put(ctx, base, f"/{index}", {"settings": {"index.number_of_shards": 1}})
        assert status_code == 200, f"expected PUT /{index} to create it, got {status_code}: {body!r}"
    status_code, body = _put(
        ctx,
        base,
        f"/{index_logged}/_settings",
        {_THRESHOLD_KEY: _THRESHOLD_LOGGED, "index.indexing.slowlog.level": "warn"},
    )
    assert status_code == 200, (
        f"expected the slowlog threshold update on {index_logged} to be accepted, got "
        f"{status_code}: {body!r}"
    )
    got_threshold = _settings_value(_get(ctx, base, f"/{index_logged}/_settings"), index_logged)
    assert got_threshold == _THRESHOLD_LOGGED, (
        f"expected {_THRESHOLD_KEY} on {index_logged} to round-trip as {_THRESHOLD_LOGGED!r}, got "
        f"{got_threshold!r}"
    )
    quiet_settings = _get(ctx, base, f"/{index_quiet}/_settings")[index_quiet]["settings"]
    assert "slowlog" not in json.dumps(quiet_settings), (
        f"expected the twin {index_quiet} to carry NO slowlog setting (untouched), got "
        f"{quiet_settings!r}"
    )

    # --- 7. One write per index, each carrying a marker unique to it.
    marker_logged = ctx.unique_name("osidxlogged")
    marker_quiet = ctx.unique_name("osidxquiet")
    written_at = time.monotonic()
    for index, marker in ((index_logged, marker_logged), (index_quiet, marker_quiet)):
        status_code, body = _put(ctx, base, f"/{index}/_doc/1?refresh=true", {"body": marker})
        assert status_code == 201, (
            f"expected the write to {index} to succeed so both arms did equal work, got HTTP "
            f"{status_code}: {body!r}"
        )
        assert body.get("result") == "created", (
            f"expected the write to {index} to create document 1, got {body!r}"
        )

    # --- 8. Terminal read AT THE CONSUMER: the INDEX_SLOW_LOGS group in CloudWatch Logs.
    delivered = _poll_until(
        lambda: _log_messages(logs, index_group),
        lambda msgs: any(index_logged in m and "took" in m for m in msgs),
        timeout_s=900.0,
        interval_s=15.0,
        description=(
            f"an INDEX_SLOW_LOGS line naming {index_logged} and carrying `took` is delivered to "
            f"log group {index_group}"
        ),
    )
    latency_s = time.monotonic() - written_at
    hit_lines = [m for m in delivered if index_logged in m and "took" in m]
    assert any(marker_logged in m for m in hit_lines), (
        f"expected the delivered index slow-log line to carry the written document's marker "
        f"{marker_logged!r} in its source[...] clause, joining the write to the event; got "
        f"{[m[:300] for m in hit_lines]}"
    )

    # --- 9. Absences, held for a window sized from the measured latency and re-polled throughout:
    # the untouched twin produced no INDEX_SLOW_LOGS line, and the slow-log line did not leak into
    # the ES_APPLICATION_LOGS group.
    hold_s = min(max(3.0 * latency_s, 30.0), 300.0)
    deadline = time.monotonic() + hold_s
    while True:
        current = _log_messages(logs, index_group)
        offenders = [m for m in current if index_quiet in m or marker_quiet in m]
        assert not offenders, (
            f"expected NO INDEX_SLOW_LOGS line for the untouched twin {index_quiet}: it has no "
            f"slowlog threshold, while {index_logged} on the same domain delivered "
            f"{latency_s:.0f}s after an identical write; got {[m[:300] for m in offenders]}"
        )
        server_side = logs.filter_log_events(
            logGroupName=index_group, filterPattern=f'"{marker_quiet}"', limit=10
        )["events"]
        assert not server_side, (
            f"expected FilterLogEvents' server-side match for {marker_quiet!r} in {index_group} to "
            f"return nothing, got {server_side!r}"
        )
        assert any(index_logged in m for m in current), (
            f"expected the positive control's line for {index_logged} to remain present "
            f"throughout the hold, got {len(current)} messages without it"
        )
        app_lines = _log_messages(logs, app_group)
        crossed = [m for m in app_lines if marker_logged in m or marker_quiet in m]
        assert not crossed, (
            f"expected the ES_APPLICATION_LOGS group {app_group} never to receive an indexed "
            f"document's slow-log line, got {[m[:300] for m in crossed]}"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(2)


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _log_group_with_es_policy(ctx, logs, group_name, account, domain_arn) -> str:
    """Create *group_name*, register its teardown, attach a RESOURCE-scoped policy granting
    es.amazonaws.com CreateLogStream + PutLogEvents scoped to this domain, and return the group
    ARN WITHOUT the ':*' suffix describe_log_groups appends (the resource-scoped policy APIs and
    LogPublishingOptions take the bare form)."""
    logs.create_log_group(logGroupName=group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    listed = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"]
    assert [g["logGroupName"] for g in listed] == [group_name], (
        f"expected exactly the log group {group_name} under its own unique prefix, got {listed!r}"
    )
    raw_arn = listed[0]["arn"]
    group_arn = raw_arn[: -len(":*")] if raw_arn.endswith(":*") else raw_arn
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOpenSearchLogDelivery",
                "Effect": "Allow",
                "Principal": {"Service": ["es.amazonaws.com"]},
                "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                # A resource-scoped policy takes exactly ONE Resource, in the stream-wildcard form.
                "Resource": f"{group_arn}:*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnLike": {"aws:SourceArn": domain_arn},
                },
            }
        ],
    }
    logs.put_resource_policy(policyDocument=json.dumps(policy_doc), resourceArn=group_arn)
    ctx.on_cleanup(lambda: _delete_resource_policy(logs, group_arn))
    stored = logs.describe_resource_policies(resourceArn=group_arn, policyScope="RESOURCE")[
        "resourcePolicies"
    ]
    assert len(stored) == 1, (
        f"expected exactly 1 RESOURCE-scoped policy on {group_name}, got {len(stored)}: {stored!r}"
    )
    principals = {
        p
        for stmt in json.loads(stored[0]["policyDocument"])["Statement"]
        for p in _as_list(stmt["Principal"]["Service"])
    }
    assert principals == {"es.amazonaws.com"}, (
        f"expected the stored policy on {group_name} to grant es.amazonaws.com only, got "
        f"{sorted(principals)}"
    )
    return group_arn


def _account_access_policy(ctx, domain_name: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "es:*",
                    "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
                }
            ],
        }
    )


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown that is NOT silent about anything but not-found. DeleteDomain is
    asynchronous and returns immediately."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_domain(ctx, osc, domain_name: str) -> None:
    """Cleanup is registered BEFORE the create so a failure in between cannot leak a cluster."""
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = {
        "DomainName": domain_name,
        "EngineVersion": _ENGINE_VERSION,
        "ClusterConfig": dict(_MIN_CLUSTER_CONFIG),
        "EBSOptions": dict(_MIN_EBS_OPTIONS),
        "AccessPolicies": _account_access_policy(ctx, domain_name),
        "TagList": [{"Key": "sim2real", "Value": CHECK}],
    }
    last_code = None
    for attempt in range(12):
        try:
            osc.create_domain(**kwargs)
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt))
    raise AssertionError(
        f"CreateDomain for {domain_name} still throttled after 12 attempts (last code "
        f"{last_code!r})"
    )


def _update_log_publishing(osc, domain_name: str, options: dict):
    """UpdateDomainConfig(LogPublishingOptions=options). Returns None when accepted, else the
    (code, message) it was refused with. The one retried refusal is AWS's self-describing
    "A change/update is in progress", which DescribeDomain's Processing flag can lag by seconds;
    any other refusal is returned to the caller to assert on."""
    last = None
    for attempt in range(12):
        try:
            osc.update_domain_config(DomainName=domain_name, LogPublishingOptions=options)
            return None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "change/update is in progress" in message:
                last = message
                time.sleep(5.0 * (1 + attempt))
                continue
            return code, message
    raise AssertionError(
        f"UpdateDomainConfig for {domain_name} still refused as in-progress after 12 attempts "
        f"(last message {last!r})"
    )


def _wait_settled(osc, domain_name: str, timeout_s: float) -> str:
    """Poll until DescribeDomain reports Processing=False with an Endpoint AND every configured
    log-publishing option has reached OptionStatus.State=Active -- the second half is the
    observable that the publishing change itself has landed, not merely that Processing has yet to
    flip. Returns the endpoint."""
    last: dict = {}

    def _probe():
        status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        cfg = osc.describe_domain_config(DomainName=domain_name)["DomainConfig"]
        lp_state = (cfg.get("LogPublishingOptions") or {}).get("Status", {}).get("State")
        last.update(
            {
                "Processing": status.get("Processing"),
                "Endpoint": status.get("Endpoint"),
                "LogPublishingState": lp_state,
                "LogPublishingOptions": status.get("LogPublishingOptions"),
            }
        )
        return dict(last)

    _poll_until(
        _probe,
        lambda s: s["Processing"] is False
        and s["Endpoint"]
        and s["LogPublishingState"] in (None, "Active"),
        timeout_s=timeout_s,
        interval_s=20.0,
        description=(
            f"domain {domain_name} settles (Processing=False, an Endpoint, log publishing Active)"
        ),
    )
    return last["Endpoint"]


def _signed_request(ctx, method, url, body=None):
    """SigV4-signed ('es') HTTPS request to the domain endpoint -> (status, parsed json), signed
    with the credentials ctx wired, sent with stdlib urllib."""
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    assert signer_creds is not None, (
        "expected ctx to have wired AWS credentials for signing OpenSearch data-plane requests"
    )
    frozen = signer_creds.get_frozen_credentials()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AssertionError(
            f"signed {method} {url} did not complete against an endpoint the target published: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _put(ctx, base, path, body):
    return _signed_request(ctx, "PUT", f"{base}{path}", body)


def _get(ctx, base, path):
    status, body = _signed_request(ctx, "GET", f"{base}{path}")
    assert status == 200, f"expected HTTP 200 from GET {path}, got {status}: {body!r}"
    return body


def _wait_data_plane_ready(ctx, base: str, timeout_s: float) -> None:
    """Processing=False plus an Endpoint does NOT mean the data-plane authorizer has the access
    policy yet; signed requests legitimately 403 for a while after that."""
    _poll_until(
        lambda: _signed_request(ctx, "GET", f"{base}/")[0],
        lambda status: status == 200,
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"the domain data plane at {base} answers GET / with 200",
    )


def _settings_value(settings_body: dict, index: str):
    """GET /<index>/_settings returns the key either flattened or nested; read both spellings of
    the SAME answer rather than guessing which."""
    flat = settings_body[index]["settings"]
    if _THRESHOLD_KEY in flat:
        return flat[_THRESHOLD_KEY]
    node = flat
    for part in _THRESHOLD_KEY.split("."):
        if not isinstance(node, dict) or part not in node:
            raise AssertionError(
                f"expected {_THRESHOLD_KEY!r} in the settings for {index} in flattened or nested "
                f"form, got {flat!r}"
            )
        node = node[part]
    return node


def _log_messages(logs, group_name: str) -> list[str]:
    """Every message in a log group this check created, fully paginated: a FilterLogEvents page
    may be partially full or empty while a nextToken is still present."""
    messages: list[str] = []
    next_token = None
    while True:
        kwargs = {"logGroupName": group_name, "limit": 200}
        if next_token is not None:
            kwargs["nextToken"] = next_token
        try:
            resp = logs.filter_log_events(**kwargs)
        except logs.exceptions.ResourceNotFoundException as exc:
            raise AssertionError(
                f"log group {group_name} created by this check is not readable: {exc}"
            ) from exc
        messages.extend(e["message"] for e in resp["events"])
        next_token = resp.get("nextToken")
        if next_token is None:
            return messages


def _delete_resource_policy(logs, arn) -> None:
    """Delete a log group's resource policy at its current revision; a concurrent update retries."""
    for attempt in range(5):
        policies = logs.describe_resource_policies(resourceArn=arn, policyScope="RESOURCE").get(
            "resourcePolicies", []
        )
        if not policies:
            return
        try:
            logs.delete_resource_policy(resourceArn=arn, expectedRevisionId=policies[0]["revisionId"])
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if e.response["Error"]["Code"] != "InvalidParameterException" or attempt == 4:
                raise
            time.sleep(3.0 * (attempt + 1))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
