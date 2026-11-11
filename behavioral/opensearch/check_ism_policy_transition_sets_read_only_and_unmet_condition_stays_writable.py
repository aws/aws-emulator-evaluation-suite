"""ism-policy-transition-sets-read-only-and-unmet-condition-stays-writable."""
from __future__ import annotations

import http.client
import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "ism-policy-transition-sets-read-only-and-unmet-condition-stays-writable"
GROUP = 'data-plane'
SERVICES = ['opensearch']


ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology: domains bill per node-hour, so provision the cheapest
# legal cluster and register teardown before create.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Marks a domain endpoint the target published and then failed to answer on.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created or is already deleted.

    Any other failure raises, because ``ctx.on_cleanup`` swallows exceptions and a leak would be silent.
    """
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource-based policy letting this account's principals use the data plane."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _create_min_domain(ctx, *, scenario: str, **overrides) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    # Registered before the create so a failure in between can never leak a 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        # Tagged at creation so tag-based cleanup can find it if this check's cleanup never runs.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: back off on throttling.
    for attempt in range(12):
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False and a published Endpoint; a provision here takes ~600-850 s."""
    osc = ctx.client("opensearch")
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last: dict = {}
    while True:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to publish a searchable endpoint: the run budget ended first; not graded")
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials, not boto3's ambient chain: the wrong principal gets a 403.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    if raw is not None:
        data = raw if isinstance(raw, bytes) else raw.encode()
    elif body is not None:
        data = json.dumps(body).encode()
    else:
        data = None
    headers = {"Content-Type": content_type} if data is not None else {}
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
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        # An HTTP status is data the caller asserts on; a transport failure on an endpoint the
        # target itself published is the target's failure, so it is reported with the marker.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Poll a cheap signed GET until it stops 403ing.

    A published Endpoint does not mean the data-plane authorizer has the access policy yet.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while True:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError("the domain data plane to stop answering 403: the run budget ended first; not graded")
    raise _never_ready(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _error_type(payload) -> str:
    """``error.type`` of an engine error ({'error': {'type': ..., 'reason': ...}, 'status': n}).

    The engine puts the wrapper type here and the underlying one in ``error.root_cause[0].type``.
    """
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _error_reason(payload) -> str:
    """The engine's ``error.reason`` string, for an exact-message assertion."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("reason") or "")
    return ""


def _create_index(ctx, base: str, index: str) -> None:
    """One shard, no replica: a single-node cluster never allocates a replica, and a yellow/red
    index would make later ISM assertions read a shard problem instead.
    """
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    assert created.get("acknowledged") is True, (
        f"creating index {index!r} was not acknowledged: {created!r}")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))


def _index_docs(ctx, base: str, index: str, n: int) -> None:
    """Write n documents with refresh=true, then assert the searchable count.

    ISM's ``min_doc_count`` is evaluated against the doc count, so writes must be refreshed.
    """
    for i in range(n):
        status, body = _signed_request(ctx, "PUT", f"{base}/{index}/_doc/seed-{i}?refresh=true",
                                       body={"seq": i})
        assert status == 201, f"seeding {index!r} doc {i} returned HTTP {status!r}: {body!r}"
    seeded = _count(ctx, base, index)
    assert seeded == n, (
        f"index {index!r} holds {seeded!r} searchable documents after seeding {n} with "
        f"refresh=true -- ISM's min_doc_count is evaluated against this number")


def _count(ctx, base: str, index: str) -> int:
    status, body = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"_count on {index!r} returned HTTP {status!r}: {body!r}"
    return body["count"]


def _settings(ctx, base: str, index: str) -> dict:
    status, body = _signed_request(ctx, "GET", f"{base}/{index}/_settings")
    assert status == 200, f"_settings on {index!r} returned HTTP {status!r}: {body!r}"
    return body[index]["settings"]["index"]


def _explain(ctx, base: str, index: str) -> dict:
    """One index's ISM explain entry; the response is keyed by index name."""
    status, body = _signed_request(ctx, "GET", f"{base}/_plugins/_ism/explain/{index}")
    assert status == 200, f"ISM explain for {index!r} returned HTTP {status!r}: {body!r}"
    entry = body.get(index)
    assert isinstance(entry, dict), (
        f"ISM explain returned no entry for {index!r}; payload was {body!r}")
    return entry


def _step_status(entry: dict) -> str:
    return str(((entry.get("step") or {}).get("step_status")) or "")


def _state_name(entry: dict) -> str:
    return str(((entry.get("state") or {}).get("name")) or "")


def _wait_ism_both(ctx, base: str, wanted: dict, timeout_s: float) -> dict:
    """Poll ISM explain for several indices under one shared budget until every predicate holds.

    ISM runs on its own interval, which the managed service will not let a client shorten.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    seen: dict = {}
    while True:
        for index, (predicate, _what) in wanted.items():
            if index in seen:
                continue
            entry = _explain(ctx, base, index)
            if predicate(entry):
                seen[index] = entry
        if len(seen) == len(wanted):
            return seen
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"ISM to reach the expected state on {sorted(set(wanted) - set(seen))!r}: the run budget ended "
            f"first; not graded"
        )
    outstanding = {index: (what, _explain(ctx, base, index))
                   for index, (_predicate, what) in wanted.items() if index not in seen}
    raise _never_ready(
        f"ISM never reached the expected state within {timeout_s}s: "
        + "; ".join(f"index {i!r} never {w} (last explain {e!r})"
                    for i, (w, e) in outstanding.items()),
    )


_SCENARIO = "ism-transition-read-only"

# The retry block OpenSearch 2.11 injects into an action the policy did not spell one out for;
# the stored policy reads back normalised with it.
_DEFAULT_ACTION_RETRY = {"count": 3, "backoff": "exponential", "delay": "1m"}


# timing:real-time — schedule: 300 s https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ism.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """One ISM policy on two indices transitions only the one meeting ``min_doc_count``: it becomes
    read-only (writes refused, reads fine) while the other stays in condition_not_met and writable;
    a second policy attach is refused, and removing the policy and block lets the write succeed.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    # Both indices are created by this check and named uniquely, so a concurrent run cannot collide.
    met = ctx.unique_name("sim2real-behav-ism-met-")
    unmet = ctx.unique_name("sim2real-behav-ism-unmet-")
    policy_id = ctx.unique_name("sim2real-behav-ism-pol-")

    policy_body = {"policy": {
        "description": "sim2real ISM transition check",
        "default_state": "writable",
        "states": [
            {"name": "writable", "actions": [],
             "transitions": [{"state_name": "locked", "conditions": {"min_doc_count": 2}}]},
            {"name": "locked", "actions": [{"read_only": {}}], "transitions": []},
        ]}}
    status, stored = _signed_request(
        ctx, "PUT", f"{base}/_plugins/_ism/policies/{policy_id}", body=policy_body)
    assert status == 201, f"PUT ISM policy {policy_id!r} returned HTTP {status!r}: {stored!r}"
    ctx.on_cleanup(
        lambda: _signed_request(ctx, "DELETE", f"{base}/_plugins/_ism/policies/{policy_id}"))
    assert stored.get("_id") == policy_id, (
        f"the stored policy reports _id {stored.get('_id')!r}, expected {policy_id!r}: {stored!r}")
    assert stored.get("_version") == 1, (
        f"the first write of policy {policy_id!r} reports _version {stored.get('_version')!r}, "
        f"expected 1: {stored!r}")
    stored_policy = stored.get("policy", {}).get("policy", {})
    assert stored_policy.get("default_state") == "writable", (
        f"the stored policy's default_state is {stored_policy.get('default_state')!r}, expected "
        f"'writable': {stored!r}")
    assert [s["name"] for s in stored_policy.get("states", [])] == ["writable", "locked"], (
        f"the stored policy's states are "
        f"{[s.get('name') for s in stored_policy.get('states', [])]!r}, expected "
        f"['writable', 'locked']")
    locked_action = stored_policy["states"][1]["actions"][0]
    assert locked_action.get("retry") == _DEFAULT_ACTION_RETRY, (
        f"the stored read_only action carries retry {locked_action.get('retry')!r}, expected the "
        f"default {_DEFAULT_ACTION_RETRY!r} the engine injects -- a policy stored verbatim has no "
        f"retry semantics at all")

    # The ONLY difference between the two indices is the document count: two meets the transition
    # condition, one does not.
    _create_index(ctx, base, met)
    _index_docs(ctx, base, met, 2)
    _create_index(ctx, base, unmet)
    _index_docs(ctx, base, unmet, 1)

    for index in (met, unmet):
        status, added = _signed_request(
            ctx, "POST", f"{base}/_plugins/_ism/add/{index}", body={"policy_id": policy_id})
        assert status == 200, f"ISM add for {index!r} returned HTTP {status!r}: {added!r}"
        assert added.get("failures") is False, (
            f"ISM add for {index!r} reported failures={added.get('failures')!r}: {added!r}")
        assert added.get("updated_indices") == 1, (
            f"ISM add for {index!r} reports updated_indices "
            f"{added.get('updated_indices')!r}, expected 1: {added!r}")

    # Attaching a second policy to an already-managed index must be refused and must not replace
    # the attachment.
    status, again = _signed_request(
        ctx, "POST", f"{base}/_plugins/_ism/add/{met}", body={"policy_id": policy_id})
    assert status == 200, f"the duplicate ISM add returned HTTP {status!r}: {again!r}"
    assert again.get("failures") is True, (
        f"the duplicate ISM add on the already-managed {met!r} reported "
        f"failures={again.get('failures')!r}, expected True: {again!r}")
    assert again.get("updated_indices") == 0, (
        f"the duplicate ISM add reports updated_indices {again.get('updated_indices')!r}, expected "
        f"0 -- a refused attach must not count as an update: {again!r}")
    failed = again.get("failed_indices") or []
    assert [f.get("index_name") for f in failed] == [met], (
        f"the duplicate ISM add named {[f.get('index_name') for f in failed]!r} as failed, expected "
        f"[{met!r}]: {again!r}")
    assert failed[0].get("reason") == (
        "This index already has a policy, use the update policy API to update index policies"), (
        f"the duplicate ISM add's reason is {failed[0].get('reason')!r}, expected the exact "
        f"already-has-a-policy message that names the update API: {again!r}")

    # The met index must reach the locked state with read_only completed; the unmet index must be
    # evaluated and refused (`condition_not_met`), a positive observation of the negative outcome.
    observed = _wait_ism_both(ctx, base, {
        met: (lambda e: _state_name(e) == "locked" and _step_status(e) == "completed",
              "transitioned to the locked state with its action completed"),
        unmet: (lambda e: _step_status(e) == "condition_not_met",
                "was evaluated against the transition condition and refused"),
    }, 1200.0)
    met_entry, unmet_entry = observed[met], observed[unmet]

    assert met_entry.get("policy_id") == policy_id, (
        f"the transitioned index reports policy_id {met_entry.get('policy_id')!r}, expected "
        f"{policy_id!r} -- the duplicate add must not have replaced it: {met_entry!r}")
    assert (met_entry.get("action") or {}).get("name") == "read_only", (
        f"the locked state ran action {(met_entry.get('action') or {}).get('name')!r}, expected "
        f"'read_only': {met_entry!r}")
    assert (met_entry.get("action") or {}).get("failed") is False, (
        f"the read_only action reports failed={(met_entry.get('action') or {}).get('failed')!r}, "
        f"expected False: {met_entry!r}")
    assert (met_entry.get("step") or {}).get("name") == "set_read_only", (
        f"the completed step is {(met_entry.get('step') or {}).get('name')!r}, expected "
        f"'set_read_only': {met_entry!r}")
    assert (met_entry.get("info") or {}).get("message") == (
        f"Successfully set index to read-only [index={met}]"), (
        f"explain's info message is {(met_entry.get('info') or {}).get('message')!r}, expected the "
        f"exact success message naming the index: {met_entry!r}")
    assert (met_entry.get("retry_info") or {}).get("failed") is False, (
        f"the transitioned index reports retry_info {met_entry.get('retry_info')!r}, expected a "
        f"clean run: {met_entry!r}")

    # The effect, read off the index rather than off the policy that asked for it.
    met_settings = _settings(ctx, base, met)
    assert met_settings.get("blocks", {}).get("write") == "true", (
        f"after the transition {met!r} has index.blocks {met_settings.get('blocks')!r}, expected "
        f"write 'true' -- a state machine that reports 'Successfully set index to read-only' and "
        f"leaves the index writable has done nothing")
    status, refused = _signed_request(ctx, "PUT", f"{base}/{met}/_doc/post-lock",
                                      body={"seq": 99})
    assert status == 403, (
        f"writing to the read-only {met!r} returned HTTP {status!r}, expected 403: {refused!r}")
    assert _error_type(refused) == "cluster_block_exception", (
        f"the refused write reports error type {_error_type(refused)!r}, expected "
        f"'cluster_block_exception': {refused!r}")
    assert _error_reason(refused) == (
        f"index [{met}] blocked by: [FORBIDDEN/8/index write (api)];"), (
        f"the refused write's reason is {_error_reason(refused)!r}, expected the exact "
        f"FORBIDDEN/8 index-write block naming {met!r}: {refused!r}")
    assert _count(ctx, base, met) == 2, (
        f"{met!r} holds {_count(ctx, base, met)!r} documents after the refused write, expected the "
        f"2 written before the transition -- a refusal that stored the document is not a refusal")
    # read_only blocks writes ONLY: the search path must be untouched.
    status, searched = _signed_request(ctx, "POST", f"{base}/{met}/_search",
                                       body={"size": 10, "query": {"match_all": {}}})
    assert status == 200, f"searching the read-only {met!r} returned HTTP {status!r}: {searched!r}"
    assert sorted(h["_id"] for h in searched["hits"]["hits"]) == ["seed-0", "seed-1"], (
        f"searching the read-only {met!r} returned "
        f"{sorted(h['_id'] for h in searched['hits']['hits'])!r}, expected both seeded ids -- "
        f"read_only must not block reads")

    # The same policy, one document short: evaluated, refused, and no effect anywhere.
    assert _state_name(unmet_entry) == "writable", (
        f"the one-document-short {unmet!r} is in state {_state_name(unmet_entry)!r}, expected to "
        f"still be in the policy's default 'writable' state: {unmet_entry!r}")
    assert (unmet_entry.get("action") or {}).get("name") == "transition", (
        f"the unmet index's current action is {(unmet_entry.get('action') or {}).get('name')!r}, "
        f"expected 'transition': {unmet_entry!r}")
    assert (unmet_entry.get("step") or {}).get("name") == "attempt_transition_step", (
        f"the unmet index's step is {(unmet_entry.get('step') or {}).get('name')!r}, expected "
        f"'attempt_transition_step': {unmet_entry!r}")
    assert (unmet_entry.get("info") or {}).get("message") == (
        f"Evaluating transition conditions [index={unmet}]"), (
        f"the unmet index's info message is "
        f"{(unmet_entry.get('info') or {}).get('message')!r}, expected the exact evaluating "
        f"message naming the index: {unmet_entry!r}")
    unmet_settings = _settings(ctx, base, unmet)
    assert "blocks" not in unmet_settings, (
        f"the one-document-short {unmet!r} carries index.blocks {unmet_settings.get('blocks')!r}; "
        f"an unmet condition must leave no block behind: {unmet_settings!r}")
    status, allowed = _signed_request(ctx, "PUT", f"{base}/{unmet}/_doc/post-eval?refresh=true",
                                      body={"seq": 1})
    assert status == 201, (
        f"writing to the still-writable {unmet!r} returned HTTP {status!r}, expected 201 -- "
        f"without this the refusal above could not be told from a target that blocks every write: "
        f"{allowed!r}")
    assert allowed.get("result") == "created", (
        f"the write to {unmet!r} reports result {allowed.get('result')!r}, expected 'created': "
        f"{allowed!r}")

    # Restore: detach the policy and clear the block, and the identical refused write must succeed,
    # so the block was the policy's doing and the index is otherwise healthy.
    status, removed = _signed_request(ctx, "POST", f"{base}/_plugins/_ism/remove/{met}")
    assert status == 200, f"ISM remove for {met!r} returned HTTP {status!r}: {removed!r}"
    assert removed.get("failures") is False, (
        f"ISM remove for {met!r} reported failures={removed.get('failures')!r}: {removed!r}")
    assert removed.get("updated_indices") == 1, (
        f"ISM remove for {met!r} reports updated_indices {removed.get('updated_indices')!r}, "
        f"expected 1: {removed!r}")
    status, unblocked = _signed_request(ctx, "PUT", f"{base}/{met}/_settings",
                                       body={"index.blocks.write": None})
    assert status == 200, f"clearing index.blocks.write on {met!r} returned HTTP {status!r}: {unblocked!r}"
    assert unblocked.get("acknowledged") is True, (
        f"clearing index.blocks.write on {met!r} was not acknowledged: {unblocked!r}")
    status, restored = _signed_request(ctx, "PUT", f"{base}/{met}/_doc/post-lock?refresh=true",
                                       body={"seq": 99})
    assert status == 201, (
        f"after detaching the policy and clearing the block, the identical write to {met!r} "
        f"returned HTTP {status!r}, expected 201: {restored!r}")
    assert _count(ctx, base, met) == 3, (
        f"{met!r} holds {_count(ctx, base, met)!r} documents after the restored write, expected 3")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
