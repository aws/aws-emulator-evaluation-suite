"""opensearch-search-slow-logs-reach-the-log-group-only-for-an-index-over-threshold."""
from __future__ import annotations

# Log publishing is enabled with a disabled->enabled UpdateDomainConfig: the domain goes Active ->
# Processing -> Active before publishing starts ("typically 30 minutes, but can take longer" per the
# OpenSearch Service developer guide). Delivery also needs an index-level slowlog threshold.

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "opensearch-search-slow-logs-reach-the-log-group-only-for-an-index-over-threshold"
GROUP = "e2e"
SERVICES = ["logs", "opensearch"]

# Cheapest legal single-node topology; domains bill per node-hour.
_ENGINE_VERSION = "OpenSearch_2.11"
_MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
_MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# "0ms" logs every query; "-1" is the documented default and means disabled.
_THRESHOLD_LOGGED = "0ms"
_THRESHOLD_DISABLED = "-1"
_THRESHOLD_KEY = "index.search.slowlog.threshold.query.warn"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:e2e",
    "concern:eventing",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An OpenSearch domain created with SEARCH_SLOW_LOGS publishing enabled delivers a slow-log
    event to the CloudWatch Logs group for a query against an index whose slowlog threshold is
    exceeded, and delivers nothing for a twin index whose threshold is -1."""
    logs = ctx.client("logs")
    osc = ctx.client("opensearch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # --- 1. Prerequisite, created in-check: the log group and the resource policy that lets the
    # OpenSearch service principal write into it. Neither is assumed to exist. The domain name is
    # picked HERE, before the domain exists, so the policy's confused-deputy condition can name it
    # (see aws:SourceArn below).
    domain_name = ctx.unique_name("sim2real-behav-osslow-")[:28].rstrip("-")
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{domain_name}"
    group_name = ctx.unique_name("sim2real-behav-osslow-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    raw_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    # describe_log_groups appends a ":*" wildcard for backward compatibility; the resource-scoped
    # policy APIs reject that suffixed form, so it is stripped for resourceArn.
    log_group_arn = raw_arn[: -len(":*")] if raw_arn.endswith(":*") else raw_arn

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOpenSearchSlowLogDelivery",
                "Effect": "Allow",
                "Principal": {"Service": ["es.amazonaws.com"]},
                "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                # A RESOURCE-scoped policy (resourceArn= below) must name exactly ONE Resource entry
                # -- AWS rejects a list ("statement block must include exactly one resourceArn") --
                # and it must be the log-stream-wildcard form, not the bare group ARN: CreateDomain's
                # own preflight rejects the bare form with "does not grant sufficient permissions ...
                # to create a log stream".
                "Resource": f"{log_group_arn}:*",
                # AWS docs recommend also scoping to aws:SourceArn "to protect yourself against
                # the confused deputy problem" for domains on service software R20211203+, so the
                # grant can only be exercised by THIS domain.
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnLike": {"aws:SourceArn": domain_arn},
                },
            }
        ],
    }
    logs.put_resource_policy(
        policyDocument=json.dumps(policy_doc), resourceArn=log_group_arn
    )
    ctx.on_cleanup(lambda: _delete_resource_policy(logs, log_group_arn))
    # Independent read of the prerequisite: it exists, scoped to this group, before the domain
    # that depends on it is created.
    described_policies = logs.describe_resource_policies(
        resourceArn=log_group_arn, policyScope="RESOURCE"
    )["resourcePolicies"]
    assert len(described_policies) == 1, (
        f"expected exactly 1 RESOURCE-scoped policy on {group_name}, got "
        f"{len(described_policies)}: {described_policies!r}"
    )
    stored_principals = {
        p
        for stmt in json.loads(described_policies[0]["policyDocument"])["Statement"]
        for p in _as_list(stmt["Principal"]["Service"])
    }
    assert stored_principals == {"es.amazonaws.com"}, (
        f"expected the stored resource policy to grant es.amazonaws.com and nothing else, got "
        f"{sorted(stored_principals)}"
    )

    # --- 2. The domain, created WITHOUT SEARCH_SLOW_LOGS publishing (logs are disabled by
    # default -- AWS docs: "All the logs are disabled by default"). Cleanup is registered BEFORE
    # the create so a failure in between cannot leak a 24x7 cluster. Publishing is then enabled
    # by a disabled->enabled UpdateDomainConfig once the domain is Active.
    domain_name = _create_domain(ctx, osc, domain_name)
    _wait_searchable(osc, domain_name, timeout_s=1200.0)

    # UpdateDomainConfig right after Processing=False can still raise "ValidationException: A
    # change/update is in progress" (Processing lags the settle state), so it is retried.
    _enable_search_slow_logs(osc, domain_name, log_group_arn)
    endpoint = _wait_searchable(osc, domain_name, timeout_s=2400.0)
    base = ctx.endpoint_url(endpoint)

    status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
    published = status["LogPublishingOptions"]["SEARCH_SLOW_LOGS"]
    assert published["Enabled"] is True, (
        f"expected DescribeDomain to report SEARCH_SLOW_LOGS Enabled=True for {domain_name}, got "
        f"{published!r}"
    )
    assert published["CloudWatchLogsLogGroupArn"] == log_group_arn, (
        f"expected the publishing option to name the log group this check created "
        f"({log_group_arn}), got {published.get('CloudWatchLogsLogGroupArn')!r}"
    )

    # --- 3. Two indices on the SAME domain, differing ONLY in their slowlog threshold. That makes
    # the negative a twin control group in the same instant rather than a wait, and it isolates the
    # index-level threshold as the discriminator while the domain-level option is held constant.
    index_logged = "sim2real-osslow-logged"
    index_quiet = "sim2real-osslow-quiet"
    _wait_data_plane_ready(ctx, base, timeout_s=180.0)
    for index, threshold in ((index_logged, _THRESHOLD_LOGGED), (index_quiet, _THRESHOLD_DISABLED)):
        _put(ctx, base, f"/{index}", {"settings": {"index.number_of_shards": 1}})
        # index.search.slowlog.level gates which severity the slowlog logger itself emits
        # (independent of the threshold); pin it to "warn" in case the service default is more
        # restrictive than the documented open-source default of "trace".
        _put(
            ctx,
            base,
            f"/{index}/_settings",
            {_THRESHOLD_KEY: threshold, "index.search.slowlog.level": "warn"},
        )
        stored = _get(ctx, base, f"/{index}/_settings")
        got = _settings_value(stored, index, _THRESHOLD_KEY)
        assert got == threshold, (
            f"expected {_THRESHOLD_KEY} on {index} to round-trip as {threshold!r}, got {got!r}; "
            f"the twin control is only meaningful if both thresholds were actually accepted"
        )

    marker_logged = ctx.unique_name("osslowlogged")
    marker_quiet = ctx.unique_name("osslowquiet")
    for index, marker in ((index_logged, marker_logged), (index_quiet, marker_quiet)):
        _put(ctx, base, f"/{index}/_doc/1", {"body": marker})
        _post(ctx, base, f"/{index}/_refresh", None)

    # --- 4. One query per index, carrying a term unique to that index, issued back to back.
    queried_at = time.monotonic()
    for index, marker in ((index_logged, marker_logged), (index_quiet, marker_quiet)):
        status_code, body = _post(
            ctx, base, f"/{index}/_search", {"query": {"match": {"body": marker}}}
        )
        assert status_code == 200, (
            f"expected the search against {index} to succeed so both arms did equal work, got "
            f"HTTP {status_code}: {body!r}"
        )
        hits = body["hits"]["hits"]
        assert len(hits) == 1, (
            f"expected the query for {marker!r} to match its one document in {index}, got "
            f"{len(hits)} hits: {body['hits']!r}"
        )

    # --- 5. Terminal read AT THE CONSUMER: CloudWatch Logs, a different service reached through a
    # different operation than the OpenSearch data-plane search that caused the event.
    delivered = _poll_until(
        lambda: _log_messages(logs, group_name),
        lambda msgs: any(index_logged in m for m in msgs),
        timeout_s=900.0,
        interval_s=15.0,
        description=(
            f"a SEARCH_SLOW_LOGS event mentioning index {index_logged} (threshold "
            f"{_THRESHOLD_LOGGED}) is delivered to log group {group_name}"
        ),
    )
    latency_s = time.monotonic() - queried_at
    hit_lines = [m for m in delivered if index_logged in m]
    assert any("took" in m for m in hit_lines), (
        f"expected the delivered slow-log line for {index_logged} to carry a 'took' duration -- "
        f"that is what makes it a SLOW log rather than an arbitrary message; got "
        f"{[m[:200] for m in hit_lines]}"
    )
    assert any(marker_logged in m for m in hit_lines), (
        f"expected the delivered slow-log line to carry the query's own marker term "
        f"{marker_logged!r} from its source[...] clause, joining the query issued to the event "
        f"delivered; got {[m[:200] for m in hit_lines]}"
    )

    # --- 6. Twin control: the -1 index delivered nothing. Bounded by the positive control's own
    # delivery latency, re-polled throughout so a late arrival cannot slip
    # past a single-shot read, and confirmed through a SECOND, server-side observable
    # (FilterLogEvents' own filterPattern) rather than only a client-side scan.
    hold_s = min(max(3.0 * latency_s, 30.0), 300.0)
    deadline = time.monotonic() + hold_s
    while True:
        current = _log_messages(logs, group_name)
        offenders = [m for m in current if index_quiet in m or marker_quiet in m]
        assert not offenders, (
            f"expected NO slow-log event for {index_quiet}: its {_THRESHOLD_KEY} is "
            f"{_THRESHOLD_DISABLED!r}, and its twin {index_logged} on the same domain and log "
            f"group delivered {latency_s:.0f}s after an identical query -- so the wiring "
            f"demonstrably works and the threshold is the only difference; got "
            f"{[m[:200] for m in offenders]}"
        )
        server_side = logs.filter_log_events(
            logGroupName=group_name, filterPattern=f'"{marker_quiet}"', limit=10
        )["events"]
        assert not server_side, (
            f"expected FilterLogEvents' server-side pattern match for {marker_quiet!r} to return "
            f"nothing (second independent observable of absence), got {server_side!r}"
        )
        assert any(index_logged in m for m in current), (
            f"expected the positive control's event for {index_logged} to remain present "
            f"throughout the hold, got {len(current)} messages without it"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(2)


# ===== helpers =====
# Every timeout raises an AssertionError carrying the full last-observed state.
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
                    "Resource": (
                        f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*"
                    ),
                }
            ],
        }
    )


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: only ResourceNotFoundException is ignored, so any other delete
    failure surfaces instead of leaking the domain. DeleteDomain is asynchronous and returns
    immediately."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_domain(ctx, osc, domain_name: str) -> str:
    """No LogPublishingOptions at CREATE time -- logs are disabled by default, and enabling them
    is a separate UpdateDomainConfig transition this check exercises deliberately (see the caller:
    a same-value reassertion at create time is a no-op with nothing to converge). *domain_name* is
    picked by the caller before this runs, so the log group's resource policy can already scope
    an aws:SourceArn condition to it."""
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = {
        "DomainName": domain_name,
        "EngineVersion": _ENGINE_VERSION,
        "ClusterConfig": dict(_MIN_CLUSTER_CONFIG),
        "EBSOptions": dict(_MIN_EBS_OPTIONS),
        "AccessPolicies": _account_access_policy(ctx, domain_name),
        "TagList": [{"Key": "sim2real", "Value": CHECK}],
    }
    # CreateDomain is aggressively rate limited per account: back off on throttling only, with a
    # bounded attempt count that raises. No unconditional sleep before the first attempt.
    last_code = None
    for attempt in range(12):
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt))
    raise AssertionError(
        f"CreateDomain for {domain_name} still throttled after 12 attempts (last code "
        f"{last_code!r})"
    )


def _enable_search_slow_logs(osc, domain_name: str, log_group_arn: str) -> None:
    """UpdateDomainConfig can reject with "A change/update is in progress" for a few seconds even
    after DescribeDomain reports Processing=False -- a bounded retry on that specific message is
    the correct response (AWS's own error text says so), not a retry on ClientError generally."""
    last_message = None
    for attempt in range(12):
        try:
            osc.update_domain_config(
                DomainName=domain_name,
                LogPublishingOptions={
                    "SEARCH_SLOW_LOGS": {
                        "CloudWatchLogsLogGroupArn": log_group_arn,
                        "Enabled": True,
                    }
                },
            )
            return
        except ClientError as exc:
            last_message = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] != "ValidationException" or (
                "change/update is in progress" not in last_message
            ):
                raise
            time.sleep(5.0 * (1 + attempt))
    raise AssertionError(
        f"UpdateDomainConfig for {domain_name} still rejected as in-progress after 12 attempts "
        f"(last message {last_message!r})"
    )


def _wait_searchable(osc, domain_name: str, timeout_s: float) -> str:
    """Poll to Processing=False AND a published Endpoint; a single-node domain typically takes
    10-15 minutes to provision."""
    last: dict = {}

    def _probe():
        nonlocal last
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        return last

    _poll_until(
        _probe,
        lambda s: s.get("Processing") is False and s.get("Endpoint"),
        timeout_s=timeout_s,
        interval_s=20.0,
        description=(
            f"domain {domain_name} publishes a searchable endpoint (Processing=False and an "
            f"Endpoint)"
        ),
    )
    return last["Endpoint"]


def _signed_request(ctx, method, path, body=None):
    """SigV4-signed ('es') HTTPS request to the domain endpoint -> (status, parsed json).

    Signs with the credentials of the ctx client rather than boto3's ambient chain: signing
    as the wrong principal makes the domain's account-scoped policy 403 the request.
    Sent with stdlib urllib so no third-party HTTP client is needed.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    assert signer_creds is not None, (
        "expected ctx to have wired AWS credentials for signing OpenSearch data-plane requests, "
        "got none"
    )
    frozen = signer_creds.get_frozen_credentials()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=path, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(path, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        # An HTTP status is data the caller asserts on.
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # A transport failure is NOT data: the endpoint here was published by the target itself,
        # so failing to answer on it is the target's failure, not this check's environment.
        raise AssertionError(
            f"signed {method} {path} did not complete against an endpoint the target published: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _put(ctx, base, path, body):
    return _signed_request(ctx, "PUT", f"{base}{path}", body)


def _post(ctx, base, path, body):
    return _signed_request(ctx, "POST", f"{base}{path}", body)


def _get(ctx, base, path):
    status, body = _signed_request(ctx, "GET", f"{base}{path}")
    assert status == 200, f"expected HTTP 200 from GET {path}, got {status}: {body!r}"
    return body


def _wait_data_plane_ready(ctx, base: str, timeout_s: float) -> None:
    """Processing=False plus a published Endpoint does NOT mean the data-plane authorizer has the
    access policy yet; signed requests legitimately 403 for a while after that."""
    _poll_until(
        lambda: _signed_request(ctx, "GET", f"{base}/")[0],
        lambda status: status != 403,
        timeout_s=timeout_s,
        interval_s=10.0,
        description=(
            f"the domain data plane at {base} stops answering 403 (the access policy has reached "
            f"the authorizer)"
        ),
    )


def _settings_value(settings_body: dict, index: str, key: str):
    """GET /<index>/_settings returns {index: {"settings": {...}}} with the key either flattened
    or nested; read both spellings of the SAME answer rather than guessing which."""
    flat = settings_body[index]["settings"]
    if key in flat:
        return flat[key]
    node = flat
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            raise AssertionError(
                f"expected {key!r} present in the settings for {index} in either flattened or "
                f"nested form, got {flat!r}"
            )
        node = node[part]
    return node


def _log_messages(logs, group_name: str) -> list[str]:
    """Every message currently in the log group. The group was created by this check, so nothing
    else writes to it and a fully-paginated read is exact.

    FilterLogEvents' docs say a page "might only be partially full, or even empty" while a
    nextToken is still present, so a single un-paginated call cannot tell that gap from a
    genuinely empty group.
    """
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
