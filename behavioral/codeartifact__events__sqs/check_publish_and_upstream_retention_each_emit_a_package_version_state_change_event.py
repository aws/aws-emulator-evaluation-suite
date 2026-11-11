"""publish-and-upstream-retention-each-emit-a-package-version-state-change-event."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "publish-and-upstream-retention-each-emit-a-package-version-state-change-event"
GROUP = "event-propagation"
SERVICES = ["codeartifact", "events", "sqs"]

# EventBridge delivery of service events is "near real time", not synchronous.
_EVENT_WAIT_SECONDS = 300.0

# How long CodeArtifact may take to materialise a retained upstream copy.
_RETENTION_WAIT_SECONDS = 120.0

# Two event waits, a retention wait, a 10s dedup window and setup/teardown.
_TOTAL_BUDGET_SECONDS = 780.0

# A fixed duplicate window, read with 2 s long polls.
_DEDUP_WINDOW_SECONDS = 10.0
_POLL_SECONDS = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _long_poll_s(deadline: float, cap_s: int) -> int:
    """An SQS WaitTimeSeconds that does not run past *deadline*."""
    return max(0, min(cap_s, int(deadline - time.monotonic())))


@tags("axis:happy-path", "cap:c2", "concern:eventing", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """An npm publish and an upstream retention each deliver one CodeArtifact Package Version
    State Change event to SQS whose revision matches DescribePackageVersion; the retention event
    names the downstream repository.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-codeartifact.html
    """
    started = time.monotonic()
    ca = ctx.client("codeartifact")
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]

    domain = ctx.unique_name("sim2real-ca-dom-")
    upstream = ctx.unique_name("sim2real-ca-up-")
    downstream = ctx.unique_name("sim2real-ca-down-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=upstream,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, upstream))
    ca.create_repository(domain=domain, repository=downstream,
                         upstreams=[{"repositoryName": upstream}],
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, downstream))

    # Scoped to this domain so unrelated CodeArtifact traffic in the account cannot match.
    rule = ctx.unique_name("sim2real-ca-rule-")
    pattern = {
        "source": ["aws.codeartifact"],
        "detail-type": ["CodeArtifact Package Version State Change"],
        "detail": {"domainName": [domain]},
    }
    rule_arn = events.put_rule(Name=rule, EventPattern=json.dumps(pattern),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule))
    queue_url, queue_arn = _events_queue(ctx, rule_arn)
    events.put_targets(Rule=rule, Targets=[{"Id": "t1", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["t1"]))

    described = events.describe_rule(Name=rule)
    assert described["State"] == "ENABLED", (
        f"the rule is {described['State']!r}, expected ENABLED — a disabled rule would make every "
        f"delivery assertion below unfalsifiable"
    )
    targets = events.list_targets_by_rule(Rule=rule)["Targets"]
    assert [t["Arn"] for t in targets] == [queue_arn], (
        f"the rule's targets are {[t['Arn'] for t in targets]!r}, expected exactly the queue "
        f"{queue_arn!r}"
    )

    token = ca.get_authorization_token(domain=domain,
                                       durationSeconds=43200)["authorizationToken"]
    up_endpoint = ca.get_repository_endpoint(domain=domain, repository=upstream,
                                             format="npm")["repositoryEndpoint"]
    down_endpoint = ca.get_repository_endpoint(domain=domain, repository=downstream,
                                              format="npm")["repositoryEndpoint"]

    package = ctx.unique_name("sim2real-evt-")
    payload = b"sim2real codeartifact eventing payload\n"
    tarball = _npm_tarball(package, "1.0.0", payload)

    published_at = time.time()
    status, body = _http(ctx, up_endpoint + urllib.parse.quote(package, safe=""), method="PUT",
                         token=token, content_type="application/json",
                         body=_npm_publish_envelope(package, "1.0.0", tarball))
    assert status == 200, f"npm publish into {upstream!r} returned {status!r}: {body[:300]!r}"

    up_revision = ca.describe_package_version(
        domain=domain, repository=upstream, format="npm", package=package,
        packageVersion="1.0.0")["packageVersion"]["revision"]

    publish_event = _await_event(
        ctx, queue_url,
        lambda e: e["detail"].get("repositoryName") == upstream
        and e["detail"].get("packageName") == package,
        timeout_s=_budget_s(ctx, _EVENT_WAIT_SECONDS),
        reason=f"the publish of {package}@1.0.0 into {upstream}")

    # The double slash is the empty namespace of an un-scoped npm package.
    expected_arn = (f"arn:aws:codeartifact:{ctx.region}:{account}:package/{domain}/{upstream}"
                    f"/npm//{package}")
    _assert_envelope(publish_event, account=account, region=ctx.region, domain=domain,
                     repository=upstream, package=package, expected_arn=expected_arn)

    detail = publish_event["detail"]
    assert detail["packageVersionRevision"] == up_revision, (
        f"the event carries packageVersionRevision {detail['packageVersionRevision']!r} but "
        f"DescribePackageVersion reports revision {up_revision!r} for {package}@1.0.0 in "
        f"{upstream!r} — the event must name the revision the service actually minted"
    )
    assert detail["packageVersionState"] == "Published", (
        f"the publish event reports packageVersionState {detail['packageVersionState']!r}, "
        f"expected 'Published' for a completed npm publish"
    )
    assert detail["operationType"] == "Created", (
        f"the publish event reports operationType {detail['operationType']!r}, expected 'Created' "
        f"for a version that did not exist a moment earlier"
    )
    changes = detail["changes"]
    assert (changes["assetsAdded"], changes["assetsRemoved"], changes["assetsUpdated"]) == (1, 0, 0), (
        f"the publish event reports changes {changes!r}; one npm tarball was published, so "
        f"expected assetsAdded=1, assetsRemoved=0, assetsUpdated=0"
    )
    assert changes["statusChanged"] is True and changes["metadataUpdated"] is True, (
        f"the publish event reports changes {changes!r}; a brand-new version both gains a status "
        f"and gains metadata, so both flags must be true"
    )
    assert isinstance(detail["sequenceNumber"], int) and detail["sequenceNumber"] >= 1, (
        f"sequenceNumber is {detail['sequenceNumber']!r}; it must be a positive integer so later "
        f"events about this version can be ordered against it"
    )
    delivery_latency = time.time() - published_at
    assert delivery_latency <= _EVENT_WAIT_SECONDS, (
        f"the publish event took {delivery_latency:.1f}s to reach the queue, over the "
        f"{_EVENT_WAIT_SECONDS}s budget"
    )

    # Exactly one event per trigger in a single-account domain: the docs say a duplicate is
    # delivered only when the domain owner and repository administrator are DIFFERENT accounts.
    extra = _drain_matching(
        ctx, queue_url,
        lambda e: e["detail"].get("repositoryName") == upstream
        and e["detail"].get("packageName") == package,
        window_s=_DEDUP_WINDOW_SECONDS)
    assert extra == [], (
        f"{len(extra)} further event(s) arrived for the same publish "
        f"({[e['detail'].get('eventDeduplicationId') for e in extra]!r}); the domain owner and the "
        f"repository administrator are the same account, so exactly one event is delivered"
    )

    # Fetching through the downstream repository retains a copy there, which emits its own event.
    pre = _rejection(lambda: ca.describe_package_version(
        domain=domain, repository=downstream, format="npm", package=package,
        packageVersion="1.0.0"))
    absent = f"The npm package '{package}' does not exist in repository '{downstream}'."
    assert (pre.get("Code"), pre.get("Message")) == ("ResourceNotFoundException", absent), (
        f"the downstream repository already held {package}@1.0.0 before any fetch ({pre!r}); the "
        f"retention event below would then be about nothing"
    )

    fetched_at = time.time()
    pm_status, pm_body = _http(ctx, down_endpoint + urllib.parse.quote(package, safe=""), token=token)
    assert pm_status == 200, (
        f"the downstream endpoint returned {pm_status!r} for a package only {upstream!r} holds: "
        f"{pm_body[:300]!r}"
    )
    tarball_url = json.loads(pm_body)["versions"]["1.0.0"]["dist"]["tarball"]
    tgz_status, served = _http(ctx, tarball_url, token=token)
    assert tgz_status == 200 and served == tarball, (
        f"the downstream tarball GET returned {tgz_status!r} and {len(served)} bytes (sha256 "
        f"{hashlib.sha256(served).hexdigest()!r}); expected 200 and the {len(tarball)} published "
        f"bytes (sha256 {hashlib.sha256(tarball).hexdigest()!r})"
    )

    down_revision = _poll(
        ctx,
        lambda: _revision_or_none(ca, domain, downstream, package, "1.0.0"),
        lambda r: r is not None, timeout_s=_budget_s(ctx, _RETENTION_WAIT_SECONDS),
        interval_s=_POLL_SECONDS,
        reason=f"{package}@1.0.0 to be retained in {downstream}")

    retention_event = _await_event(
        ctx, queue_url,
        lambda e: e["detail"].get("repositoryName") == downstream
        and e["detail"].get("packageName") == package,
        timeout_s=_budget_s(ctx, _EVENT_WAIT_SECONDS),
        reason=f"the retention of {package}@1.0.0 into {downstream} after an upstream fetch")

    retained_arn = (f"arn:aws:codeartifact:{ctx.region}:{account}:package/{domain}/{downstream}"
                    f"/npm//{package}")
    _assert_envelope(retention_event, account=account, region=ctx.region, domain=domain,
                     repository=downstream, package=package, expected_arn=retained_arn)
    rdetail = retention_event["detail"]
    assert rdetail["packageVersionRevision"] == down_revision, (
        f"the retention event carries packageVersionRevision "
        f"{rdetail['packageVersionRevision']!r} but DescribePackageVersion reports "
        f"{down_revision!r} in {downstream!r}"
    )
    assert rdetail["packageVersionState"] == "Published", (
        f"the retention event reports packageVersionState {rdetail['packageVersionState']!r}, "
        f"expected 'Published' for a retained copy of a published version"
    )
    assert rdetail["changes"]["assetsAdded"] == 1, (
        f"the retention event reports changes {rdetail['changes']!r}; retaining the version copied "
        f"its single tarball into {downstream!r}, so assetsAdded must be 1"
    )
    retention_latency = time.time() - fetched_at
    assert retention_latency <= _EVENT_WAIT_SECONDS + _RETENTION_WAIT_SECONDS, (
        f"the retention event took {retention_latency:.1f}s, over the "
        f"{_EVENT_WAIT_SECONDS + _RETENTION_WAIT_SECONDS}s budget"
    )

    # The two events are about the same package version in two repositories; the origin the control
    # plane reports for the downstream copy must agree with which repository the event named.
    origin = ca.describe_package_version(
        domain=domain, repository=downstream, format="npm", package=package,
        packageVersion="1.0.0")["packageVersion"]["origin"]
    assert origin["domainEntryPoint"]["repositoryName"] == upstream, (
        f"the retained copy names {origin['domainEntryPoint']!r} as its entry point, expected the "
        f"upstream repository {upstream!r} whose publish produced the first event"
    )
    assert publish_event["detail"]["eventDeduplicationId"] != \
        retention_event["detail"]["eventDeduplicationId"], (
        f"both events carry eventDeduplicationId "
        f"{publish_event['detail']['eventDeduplicationId']!r}; a publish and a retention are "
        f"distinct occurrences and must not share a dedup id"
    )

    ctx.on_cleanup(lambda: _delete_package(ca, domain, upstream, package))
    ctx.on_cleanup(lambda: _delete_package(ca, domain, downstream, package))

    elapsed = time.monotonic() - started
    assert elapsed <= _TOTAL_BUDGET_SECONDS, (
        f"the body took {elapsed:.1f}s, over its own declared budget of "
        f"{_TOTAL_BUDGET_SECONDS}s; a run that needs longer than this will be cut off by the runner "
        f"and its oracle recorded wrong, so the budget must be raised deliberately rather than "
        f"exceeded silently"
    )


def _assert_envelope(event: dict, *, account: str, region: str, domain: str, repository: str,
                     package: str, expected_arn: str) -> None:
    """Every field of the documented CodeArtifact event envelope that is derivable in-check."""
    assert event["source"] == "aws.codeartifact", (
        f"the event's source is {event['source']!r}, expected 'aws.codeartifact'"
    )
    assert event["detail-type"] == "CodeArtifact Package Version State Change", (
        f"the event's detail-type is {event['detail-type']!r}, expected "
        f"'CodeArtifact Package Version State Change'"
    )
    assert event["account"] == account and event["region"] == region, (
        f"the event is stamped account={event['account']!r} region={event['region']!r}, expected "
        f"{account!r}/{region!r}"
    )
    assert event["resources"] == [expected_arn], (
        f"the event's resources are {event['resources']!r}, expected exactly [{expected_arn!r}] — "
        f"an npm package with no namespace yields the documented double slash"
    )
    detail = event["detail"]
    assert detail["domainName"] == domain, (
        f"detail.domainName is {detail['domainName']!r}, expected {domain!r}"
    )
    assert detail["domainOwner"] == account and detail["repositoryAdministrator"] == account, (
        f"detail names domainOwner={detail['domainOwner']!r} "
        f"repositoryAdministrator={detail['repositoryAdministrator']!r}, expected {account!r} for "
        f"both in a single-account domain"
    )
    assert detail["repositoryName"] == repository, (
        f"detail.repositoryName is {detail['repositoryName']!r}, expected {repository!r}"
    )
    assert detail["packageFormat"] == "npm", (
        f"detail.packageFormat is {detail['packageFormat']!r}, expected 'npm'"
    )
    assert detail["packageNamespace"] is None, (
        f"detail.packageNamespace is {detail['packageNamespace']!r}; an unscoped npm package has no "
        f"namespace and the documented event carries null"
    )
    assert detail["packageName"] == package, (
        f"detail.packageName is {detail['packageName']!r}, expected {package!r}"
    )
    assert detail["packageVersion"] == "1.0.0", (
        f"detail.packageVersion is {detail['packageVersion']!r}, expected '1.0.0'"
    )


def _events_queue(ctx, rule_arn: str) -> tuple[str, str]:
    """An SQS queue an EventBridge rule may write to, and only that rule."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-ca-evtq-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url,
                                   AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _await_event(ctx, queue_url: str, match, *, timeout_s: float, reason: str) -> dict:
    """The first delivered event satisfying *match*; raises on timeout."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=_long_poll_s(deadline, 20))
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            if match(body):
                return body
            seen.append(f"{body.get('detail', {}).get('repositoryName')}"
                        f"/{body.get('detail', {}).get('packageName')}")
    if _budget_spent(ctx):
        raise TimeoutError(f"an event for {reason}: the run budget ended first; not graded")
    raise AssertionError(
        f"no event for {reason} reached the queue within {timeout_s}s; {len(seen)} other "
        f"event(s) did arrive: {seen[:10]!r}"
    )


def _drain_matching(ctx, queue_url: str, match, *, window_s: float) -> list[dict]:
    """Every further matching event within *window_s*."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + window_s
    out: list[dict] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=_long_poll_s(deadline, 2))
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            if match(body):
                out.append(body)
    return out


def _revision_or_none(ca, domain: str, repository: str, package: str, version: str) -> str | None:
    """DescribePackageVersion's revision, or None while the version has not materialised."""
    try:
        return ca.describe_package_version(
            domain=domain, repository=repository, format="npm", package=package,
            packageVersion=version)["packageVersion"]["revision"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _poll(ctx, read, predicate, *, timeout_s: float, interval_s: float, reason: str):
    """Bounded retry on an observable condition. RAISES on timeout, naming what it waited for."""
    deadline = time.monotonic() + timeout_s
    observed = None
    while True:
        observed = read()
        if predicate(observed):
            return observed
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{reason}: the run budget ended first; not graded")
            raise AssertionError(
                f"waited {timeout_s}s for {reason}; last observation was {observed!r}"
            )
        time.sleep(interval_s)


def _rejection(fn) -> dict:
    """The Error record (Code, Message) of a call that MUST fail; raises if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"the call was expected to be rejected but returned {result!r}")


def _http(ctx, url: str, *, method: str = "GET", token: str | None = None, body: bytes | None = None,
          content_type: str | None = None, timeout_s: float = 60.0) -> tuple[int, bytes]:
    """One npm-registry-protocol exchange, returning (status, body) for any HTTP status."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if content_type:
        headers["Content-Type"] = content_type
    req = _routed_request(ctx, url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _npm_tarball(name: str, version: str, payload: bytes) -> bytes:
    """A deterministic npm tarball: gzipped tar with everything under `package/`."""
    manifest = json.dumps({"name": name, "version": version, "main": "index.js",
                           "description": "sim2real fidelity fixture", "license": "MIT"},
                          sort_keys=True, separators=(",", ":")).encode()
    buf = io.BytesIO()
    gz = gzip.GzipFile(fileobj=buf, mode="wb", mtime=0)
    with tarfile.open(fileobj=gz, mode="w") as tar:
        for member, data in (("package/package.json", manifest), ("package/index.js", payload)):
            info = tarfile.TarInfo(member)
            info.size, info.mtime, info.mode, info.uid, info.gid = len(data), 0, 0o644, 0, 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    gz.close()
    return buf.getvalue()


def _npm_publish_envelope(name: str, version: str, tarball: bytes) -> bytes:
    """The PUT body `npm publish` sends; libnpmpublish keys the attachment by the full name."""
    attachment = f"{name}-{version}.tgz"
    return json.dumps({
        "_id": name, "name": name, "description": "sim2real fidelity fixture",
        "dist-tags": {"latest": version},
        "versions": {version: {
            "name": name, "version": version, "_id": f"{name}@{version}",
            "description": "sim2real fidelity fixture", "main": "index.js", "license": "MIT",
            "dist": {
                "shasum": hashlib.sha1(tarball).hexdigest(),
                "integrity": "sha512-" + base64.b64encode(
                    hashlib.sha512(tarball).digest()).decode(),
                "tarball": f"http://localhost/{name}/-/{attachment}",
            },
        }},
        "access": "public",
        "_attachments": {attachment: {"content_type": "application/octet-stream",
                                      "data": base64.b64encode(tarball).decode(),
                                      "length": len(tarball)}},
    }).encode()


def _delete_package(ca, domain: str, repository: str, package: str) -> None:
    """DeletePackage, tolerating a package another cleanup step already removed."""
    try:
        ca.delete_package(domain=domain, repository=repository, format="npm", package=package)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_repository(ca, domain: str, repository: str, timeout_s: float = 120.0) -> None:
    """DeleteRepository, retrying while the service still sees a downstream reference."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_repository(domain=domain, repository=repository)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _delete_domain(ca, domain: str, timeout_s: float = 120.0) -> None:
    """DeleteDomain, retrying while the service still sees a repository in the domain."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
