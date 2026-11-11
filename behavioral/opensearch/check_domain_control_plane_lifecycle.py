"""domain-control-plane-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-control-plane-lifecycle"
GROUP = 'lifecycle'
SERVICES = ['opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
#: OpenSearch class budget for a domain transition (create to Active, delete to gone).
_DOMAIN_BUDGET_S = 2400.0
_ADV_KEY = "rest.action.multi.allow_explicit_index"


def _error(fn):
    """(code, HTTP status, message) of the ClientError ``fn`` raises; raises if it succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message", "") or ""
    raise AssertionError(f"the call should have been refused, but it succeeded: {resp!r}")


def _field(obj: dict, key: str, what: str):
    """obj[key], or an AssertionError naming the missing field (never a raw KeyError)."""
    if not isinstance(obj, dict) or key not in obj:
        keys = sorted(obj) if isinstance(obj, dict) else type(obj).__name__
        raise AssertionError(f"{what}: response has no {key!r} field (fields present: {keys!r})")
    return obj[key]


def _delete_domain_quietly(osc, name: str) -> None:
    """Teardown: delete the domain unless it is already gone; anything else raises."""
    try:
        osc.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _listed(osc, name: str) -> bool:
    names = osc.list_domain_names(EngineType="OpenSearch")["DomainNames"]
    return any(d["DomainName"] == name for d in names)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain -> Processing false with an Endpoint (echoes asserted) -> tags applied ->
    DeleteDomain -> not-found by name, absent from ListDomainNames, and
    UpdateDomainConfig on the dead domain refused."""
    osc = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-os-cp-")[:28].rstrip("-")
    arn = f"arn:aws:es:{ctx.region}:{ctx.account}:domain/{name}"
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "es:*",
            "Resource": f"{arn}/*",
        }],
    })
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, name))
    for attempt in range(10):
        try:
            osc.create_domain(
                DomainName=name,
                EngineVersion=ENGINE_VERSION,
                ClusterConfig=dict(CLUSTER_CONFIG),
                EBSOptions=dict(EBS_OPTIONS),
                AccessPolicies=policy,
                TagList=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(5.0 * (1 + attempt))
    else:
        raise AssertionError("CreateDomain still throttled after 10 attempts")

    # Terminal state only: done processing with a published Endpoint.
    deadline = time.monotonic() + _budget_s(ctx, _DOMAIN_BUDGET_S)
    status: dict = {}
    while time.monotonic() < deadline:
        status = _field(osc.describe_domain(DomainName=name), "DomainStatus", "DescribeDomain")
        if status.get("Processing") is False and status.get("Endpoint"):
            break
        time.sleep(2.0)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f"domain {name} to become active: the run budget ended first; not graded")
        raise AssertionError(
            f"domain never became active with an endpoint within {_DOMAIN_BUDGET_S}s "
            f"(Processing={status.get('Processing')}, Endpoint={status.get('Endpoint')})"
        )
    got_arn = _field(status, "ARN", "DescribeDomain DomainStatus")
    assert got_arn == arn, f"domain ARN expected {arn!r}, got {got_arn!r}"
    got_version = _field(status, "EngineVersion", "DescribeDomain DomainStatus")
    assert got_version == ENGINE_VERSION, (
        f"EngineVersion expected {ENGINE_VERSION!r}, got {got_version!r}"
    )
    cc = _field(status, "ClusterConfig", "DescribeDomain DomainStatus")
    assert (cc.get("InstanceType"), cc.get("InstanceCount")) == ("t3.small.search", 1), (
        f"ClusterConfig expected t3.small.search x1, got {cc!r}"
    )
    assert _listed(osc, name), f"ListDomainNames(EngineType=OpenSearch) does not list {name!r}"

    osc.add_tags(ARN=arn, TagList=[{"Key": "sim2real-phase", "Value": "tagged"}])
    tag_map = {t["Key"]: t["Value"] for t in _field(osc.list_tags(ARN=arn), "TagList", "ListTags")}
    want_tags = {"sim2real-check": CHECK, "sim2real-phase": "tagged"}
    assert {k: tag_map.get(k) for k in want_tags} == want_tags, (
        f"ListTags expected {want_tags!r} among the tags, got {tag_map!r}"
    )

    osc.delete_domain(DomainName=name)
    # Gone 1: DescribeDomain answers ResourceNotFoundException with HTTP 404 and the exact
    # message, polled to that terminal answer; the deleting interim is never asserted.
    deadline = time.monotonic() + _budget_s(ctx, _DOMAIN_BUDGET_S)
    gone = None
    while time.monotonic() < deadline:
        try:
            osc.describe_domain(DomainName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            gone = (
                exc.response["Error"]["Code"],
                exc.response["ResponseMetadata"]["HTTPStatusCode"],
                exc.response["Error"].get("Message", "") or "",
            )
            break
        time.sleep(2.0)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f"DescribeDomain to stop returning {name}: the run budget ended first; not graded")
        raise AssertionError(f"DescribeDomain still returns the domain {_DOMAIN_BUDGET_S}s after delete")
    code, http, msg = gone
    assert isinstance(http, int) and 400 <= http < 500 and msg.strip() != "", (
        f"DescribeDomain on the deleted domain: expected ResourceNotFoundException/4xx with a "
        f"non-empty message, got {code}/{http}: {msg!r}"
    )
    expected_message = f"Domain not found: {name}"
    assert msg == expected_message, f"expected the message {expected_message!r}, got {msg!r}"

    # Gone 2: ListDomainNames stops listing it (bounded convergence; AWS lists a deleted domain
    # for a while after DescribeDomain stops resolving it).
    deadline = time.monotonic() + _budget_s(ctx, 600.0)
    while True:
        if not _listed(osc, name):
            break
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"ListDomainNames to drop {name!r}: the run budget ended first; not graded")
            raise AssertionError(f"ListDomainNames still lists the deleted domain {name!r}")
        time.sleep(2.0)

    # Gone 3: the dead domain is unusable for mutation.
    code, http, msg = _error(
        lambda: osc.update_domain_config(DomainName=name, AdvancedOptions={_ADV_KEY: "true"})
    )
    assert code == "ResourceNotFoundException" and isinstance(http, int) and 400 <= http < 500 and msg.strip() != "", (
        f"UpdateDomainConfig on the deleted domain: expected ResourceNotFoundException/4xx with a "
        f"non-empty message, got {code}/{http}: {msg!r}"
    )
    expected_message = f"Domain not found: {name}"
    assert msg == expected_message, f"expected the message {expected_message!r}, got {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
