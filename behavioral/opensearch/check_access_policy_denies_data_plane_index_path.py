"""access-policy-denies-data-plane-index-path."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "access-policy-denies-data-plane-index-path"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a
# real cost-leak class, so every check here provisions the cheapest legal cluster (one
# t3.small.search data node, no dedicated cluster manager nodes, no zone awareness, minimum gp3 volume)
# and registers teardown BEFORE the create call.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


# Prefix of the failure raised when a domain the target accepted never reaches the awaited state,
# so that outcome reads as the target's failure rather than as a local network problem.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The "resource did not converge" verdict, the same on every target.

    A state the target ACCEPTED and then never reached within the budget carries STATE_MARKER, so
    it reads as the target's answer rather than as a local environment problem. The wait that
    raises it polls the same terminal condition with the same budget on every target.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_min_domain(ctx, *, access_policies=None, **overrides) -> str:
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between create and registration can never
    # leak a 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        # Tagged at creation so a tag search can find it if cleanup is ever interrupted.
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    if access_policies is not None:
        kwargs["AccessPolicies"] = access_policies
    kwargs.update(overrides)
    for attempt in range(12):
        # CreateDomain is aggressively rate limited per account: jitter every attempt (not just
        # the first) so concurrent runs spread out, then back off further on throttling.
        time.sleep(random.uniform(0, 20.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1800.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # Concurrent domain polls in one account hit DescribeDomain's rate limit: poll again.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        if _quiescent(last) and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} never became searchable within {budget}s "
        f"(Processing={last.get('Processing')}, "
        f"DomainProcessingStatus={last.get('DomainProcessingStatus')}, "
        f"Endpoint={last.get('Endpoint')})",
    )


def _quiescent(status: dict) -> bool:
    """True when no change is running on the domain, so UpdateDomainConfig is accepted.

    Processing=False alone can flip before the domain's own state machine settles; a config
    update sent then is refused with "A change/update is in progress".
    """
    return (
        status.get("Processing") is False
        and status.get("UpgradeProcessing") is not True
        and status.get("DomainProcessingStatus", "Active") == "Active"
    )


def _wait_quiescent(osc, domain_name: str, timeout_s: float = 1200.0) -> None:
    """Poll DescribeDomain until no change is in progress on the domain."""
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # Concurrent domain polls in one account hit DescribeDomain's rate limit: poll again.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        if _quiescent(last):
            return
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} still had a change in progress after {timeout_s}s "
        f"(Processing={last.get('Processing')}, "
        f"DomainProcessingStatus={last.get('DomainProcessingStatus')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for THIS account (not boto3's ambient chain):
    signing as the wrong principal makes the domain's account-scoped policy 403 the request.
    Sends with stdlib urllib so no third-party HTTP client is needed.
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
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has
    the access policy yet; signed requests can 403 for a while. Poll a cheap ALLOWED path
    until it clears (the cluster root is not covered by the Deny statement under test).
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/_cluster/health")
        if status != 403:
            return
        time.sleep(2)
    raise AssertionError(f"domain data plane still 403 after {timeout_s}s (last status {status})")


# ===== end shared domain helpers =====

ALLOWED_INDEX = "sim2real-behav-allowed"
DENIED_INDEX = "sim2real-behav-denied"


def _policy(ctx, domain_name: str, *, deny: bool) -> str:
    """Allow the account on the whole domain, then optionally Deny HTTP verbs on ONE index path.

    An explicit Deny beats the Allow, so the two statements together make the domain usable
    while carving out a single index -- which is what makes the negative half of this check
    observable without locking the caller out of the control plane (UpdateDomainConfig /
    DeleteDomain are gated by IAM, not by this resource policy, so teardown still works).
    `deny=False` produces the identical document minus the Deny statement, used to restore
    access and prove the negative was the policy, not a broken domain.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}"
    statements = [
        {
            "Sid": "AllowAccount",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"{domain_arn}/*",
        },
    ]
    if deny:
        statements.append({
            "Sid": "DenyOneIndex",
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": "es:ESHttp*",
            "Resource": f"{domain_arn}/{DENIED_INDEX}/*",
        })
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _apply_access_policy(ctx, osc, domain_name: str, policy: str) -> None:
    """Update AccessPolicies (if it differs from what's stored) and wait for Active."""
    stored = osc.describe_domain_config(DomainName=domain_name)["DomainConfig"]
    if json.loads(stored["AccessPolicies"]["Options"] or "{}") == json.loads(policy):
        return
    _wait_quiescent(osc, domain_name)
    osc.update_domain_config(DomainName=domain_name, AccessPolicies=policy)
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        state = osc.describe_domain_config(DomainName=domain_name)["DomainConfig"]
        if state["AccessPolicies"]["Status"]["State"] == "Active":
            _wait_quiescent(osc, domain_name)
            return
        time.sleep(2)
    raise _never_ready("access policy never reached Active within budget")


def _cat_index_names(ctx, base: str):
    status, listing = _signed_request(ctx, "GET", f"{base}/_cat/indices?format=json")
    assert status == 200, f"_cat/indices failed with HTTP {status}: {listing}"
    assert isinstance(listing, list), f"_cat/indices should return a JSON array: {listing}"
    return {entry.get("index") for entry in listing}


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A signed write and search on an index path the domain's access policy explicitly denies are answered
    403 and the write creates no index, while the allowed path keeps answering and the same write succeeds
    once the Deny is lifted."""
    domain = _create_min_domain(ctx)
    # The policy must name the domain, so patch it in once the (unique) name exists.
    osc = ctx.client("opensearch")
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _apply_access_policy(ctx, osc, domain, _policy(ctx, domain, deny=True))
    _wait_data_plane_ready(ctx, base)

    # Control: the allowed index path works end to end.
    status, indexed = _signed_request(
        ctx, "PUT", f"{base}/{ALLOWED_INDEX}/_doc/1", body={"title": "allowed"}
    )
    assert status in (200, 201), f"allowed index path was refused ({status}): {indexed}"
    status, refreshed = _signed_request(ctx, "POST", f"{base}/{ALLOWED_INDEX}/_refresh")
    assert status == 200, f"_refresh on the allowed index failed ({status}): {refreshed}"
    status, found = _signed_request(
        ctx, "POST", f"{base}/{ALLOWED_INDEX}/_search",
        body={"query": {"match": {"title": "allowed"}}},
    )
    assert status == 200, f"_search on the allowed index failed ({status}): {found}"
    hits = found.get("hits", {}).get("hits", [])
    assert len(hits) == 1, f"allowed index should hold exactly the one document, got {hits}"

    # Negative: a write to the denied index path must be refused by policy evaluation.
    status, denied_write = _signed_request(
        ctx, "PUT", f"{base}/{DENIED_INDEX}/_doc/1", body={"title": "denied"}
    )
    assert status == 403, (
        f"write to a Deny-covered index path must return HTTP 403, got {status}: {denied_write}"
    )
    denied_text = json.dumps(denied_write).lower()
    assert "not authorized" in denied_text or "access denied" in denied_text, (
        f"403 body must say the principal is not authorized, got {denied_write}"
    )

    # Negative: a read on the same denied path is refused too.
    status, denied_read = _signed_request(
        ctx, "POST", f"{base}/{DENIED_INDEX}/_search", body={"query": {"match_all": {}}}
    )
    assert status == 403, (
        f"search on a Deny-covered index path must return HTTP 403, got {status}: {denied_read}"
    )

    # Effect absent: the refused write did not auto-create the denied index.
    names = _cat_index_names(ctx, base)
    assert DENIED_INDEX not in names, (
        f"refused write still created the index: _cat/indices reports {sorted(names)}"
    )
    assert ALLOWED_INDEX in names, (
        f"allowed index missing from _cat/indices, so the listing is not trustworthy: "
        f"{sorted(names)}"
    )

    # Control again: the Deny is scoped, not a blanket lockout.
    status, still_ok = _signed_request(ctx, "GET", f"{base}/{ALLOWED_INDEX}/_doc/1")
    assert status == 200 and still_ok.get("found") is True, (
        f"the scoped Deny leaked onto the allowed path: {status} {still_ok}"
    )

    # Restore: lift the Deny and the identical call succeeds, so the 403 above came from the
    # policy and not from a broken path.
    _apply_access_policy(ctx, osc, domain, _policy(ctx, domain, deny=False))
    deadline = time.monotonic() + 300.0
    status, restored_write = None, None
    while time.monotonic() < deadline:
        status, restored_write = _signed_request(
            ctx, "PUT", f"{base}/{DENIED_INDEX}/_doc/1", body={"title": "denied"}
        )
        if status in (200, 201):
            break
        time.sleep(2)
    assert status in (200, 201), (
        f"identical write to the formerly Deny-covered index must succeed once the Deny is "
        f"lifted, got {status}: {restored_write}"
    )

    # Cleanup as an assertion: the extra index this check created is provably gone and unusable.
    status, deleted = _signed_request(ctx, "DELETE", f"{base}/{ALLOWED_INDEX}")
    assert status == 200, f"cleanup delete of the allowed index failed ({status}): {deleted}"
    names_after_delete = _cat_index_names(ctx, base)
    assert ALLOWED_INDEX not in names_after_delete, (
        f"deleted index still listed in _cat/indices: {sorted(names_after_delete)}"
    )
    status, dead_read = _signed_request(ctx, "GET", f"{base}/{ALLOWED_INDEX}/_doc/1")
    assert status == 404, f"read on a deleted index should 404, got {status}: {dead_read}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
