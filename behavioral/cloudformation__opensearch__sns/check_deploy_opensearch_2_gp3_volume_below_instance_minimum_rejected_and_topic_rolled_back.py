"""deploy-opensearch-2-gp3-volume-below-instance-minimum-rejected-and-topic-rolled-back."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-opensearch-2-gp3-volume-below-instance-minimum-rejected-and-topic-rolled-back"

GROUP = "deploy_rollback"

SERVICES = ["cloudformation", "opensearch", "sns"]

TEMPLATE = Path(__file__).parent / "deployments" / "domain-ebs-volume-below-instance-minimum.json"


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A gp3 volume below the instance type's minimum fails the OpenSearch 2.x Domain after its
    DependsOn topic exists; the service's own refusal text becomes the Domain's reason, and the
    rollback leaves neither the topic nor the domain behind.
    """
    cfn = ctx.client("cloudformation")
    osvc = ctx.client("opensearch")
    sns = ctx.client("sns")

    template_body = TEMPLATE.read_text()
    domain_props = json.loads(template_body)["Resources"]["Domain"]["Properties"]
    engine = domain_props["EngineVersion"]
    itype = domain_props["ClusterConfig"]["InstanceType"]
    vtype = domain_props["EBSOptions"]["VolumeType"]
    vsize = domain_props["EBSOptions"]["VolumeSize"]

    # ---- Positive control on the premise: the target itself reports the floor we violate ----
    limits = _with_throttle_retry(lambda: osvc.describe_instance_type_limits(
        InstanceType=itype, EngineVersion=engine))
    vmin, vmax = _volume_bounds(limits, vtype)
    assert vsize < vmin, (
        f"the template's {vtype} VolumeSize={vsize} is not below the floor DescribeInstanceTypeLimits "
        f"reports for {itype} on {engine} ({vmin}..{vmax}); the fault under test no longer exists"
    )

    # ---- Stack A: SNS topic, then (DependsOn) the doomed domain ----
    # The stack's CreateDomain goes first: OpenSearch rate-limits CreateDomain per account, and a
    # direct call just before it turns the Domain's failure into "Rate exceeded".
    topic_name = _xname(ctx, "topic")
    domain_name = ctx.unique_name(_XSVC_PREFIX)  # <= 28 chars, OpenSearch's domain-name ceiling
    ctx.on_cleanup(lambda: _delete_domain_if_present(osvc, domain_name))
    stack, status = _create_stack_and_wait(
        ctx, template_body, stack_name=_xname(ctx, "osrb-ebs"),
        parameters={"TopicName": topic_name, "DomainName": domain_name}, timeout_s=900.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"a Domain that fails to create must roll the whole stack back; stack {stack!r} ended "
        f"{status!r}"
    )

    # ---- The service's own refusal, captured live from a direct CreateDomain ----
    direct_domain = ctx.unique_name(_XSVC_PREFIX)
    ctx.on_cleanup(lambda: _delete_domain_if_present(osvc, direct_domain))
    direct = _expect_client_error(lambda: osvc.create_domain(
        DomainName=direct_domain, EngineVersion=engine,
        ClusterConfig=domain_props["ClusterConfig"], EBSOptions=domain_props["EBSOptions"]))
    assert direct["code"] == "LimitExceededException", (
        f"CreateDomain with {vtype} VolumeSize={vsize} on {itype} must be refused with "
        f"LimitExceededException; got {direct!r}"
    )
    want_message = (f"Volume size must be between {vmin} and {vmax} for {itype} instance type "
                    f"and version {engine}")
    assert direct["message"] == want_message, (
        f"CreateDomain's refusal text must name the bounds the service itself reported; "
        f"expected {want_message!r}, got {direct['message']!r}"
    )

    events = _stack_events(cfn, stack)
    topic_done = _one_event(events, "Topic", "CREATE_COMPLETE")
    topic_arn = topic_done.get("PhysicalResourceId") or ""
    arn = topic_arn.split(":")
    assert len(arn) == 6 and arn[:3] == ["arn", "aws", "sns"] and arn[3] == ctx.region \
        and re.fullmatch(r"\d{12}", arn[4]) and arn[5] == topic_name, (
            f"the Topic's CREATE_COMPLETE must carry the topic ARN for {topic_name!r} in "
            f"{ctx.region!r}; got {topic_arn!r}"
        )
    domain_started = _first_event(events, "Domain", "CREATE_IN_PROGRESS")
    assert topic_done["Timestamp"] <= domain_started["Timestamp"], (
        f"DependsOn: the Domain began ({domain_started['Timestamp']!r}) before the Topic "
        f"completed ({topic_done['Timestamp']!r})"
    )

    reason = _one_event(events, "Domain", "CREATE_FAILED").get("ResourceStatusReason") or ""
    # Request ID and RequestToken are minted per call; every other byte of the reason is graded.
    masked = re.sub(r"(Request ID|RequestToken): [0-9A-Za-z-]+", r"\1: <id>", reason)
    want_reason = (f'Resource handler returned message: "{want_message} (Service: OpenSearch, '
                   f'Status Code: {direct["http_status"]}, Request ID: <id>) (SDK Attempt Count: 3)" '
                   f'(RequestToken: <id>, '
                   f'HandlerErrorCode: ServiceLimitExceeded)')
    assert masked == want_reason, (
        f"the Domain's ResourceStatusReason must carry the OpenSearch service's own refusal "
        f"text verbatim; expected {want_reason!r} (ids masked), got {reason!r}"
    )
    status_in_reason = re.search(r"\(Service: OpenSearch, Status Code: (\d{3}),", reason)
    assert status_in_reason and int(status_in_reason.group(1)) == direct["http_status"], (
        f"the reason must name the same HTTP status the service returned directly "
        f"({direct['http_status']!r}); got {reason!r}"
    )
    handler_code = re.search(r"HandlerErrorCode: (\w+)\)", reason)
    assert handler_code and handler_code.group(1) == "ServiceLimitExceeded", (
        f"CloudFormation must classify a LimitExceededException as HandlerErrorCode "
        f"ServiceLimitExceeded; got {reason!r}"
    )
    rollback_reason = _one_event(events, stack, "ROLLBACK_IN_PROGRESS").get(
        "ResourceStatusReason") or ""
    assert rollback_reason == ("The following resource(s) failed to create: [Domain]. "
                               "Rollback requested by user."), (
        f"the rollback must be attributed to exactly the Domain; got {rollback_reason!r}"
    )
    topic_deleted = _one_event(events, "Topic", "DELETE_COMPLETE")
    assert topic_deleted.get("PhysicalResourceId") == topic_arn, (
        f"the rollback must delete the topic it created ({topic_arn!r}); the DELETE_COMPLETE "
        f"event names {topic_deleted.get('PhysicalResourceId')!r}"
    )

    # ---- The effect is absent in SNS ... ----
    topic_err = _expect_client_error(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    assert topic_err["code"] == "NotFound", (
        f"after ROLLBACK_COMPLETE the topic {topic_arn!r} must be gone; GetTopicAttributes "
        f"reported {topic_err!r}"
    )
    assert topic_err["message"] == "Topic does not exist", (
        f"GetTopicAttributes on the rolled-back topic must say 'Topic does not exist'; got "
        f"{topic_err['message']!r}"
    )
    assert topic_arn not in _all_topic_arns(sns), (
        f"after ROLLBACK_COMPLETE ListTopics still lists {topic_arn!r}"
    )

    # ---- ... and in OpenSearch, for both the stack's domain and the direct attempt ----
    for name in (domain_name, direct_domain):
        missing = _expect_client_error(lambda n=name: osvc.describe_domain(DomainName=n))
        assert missing["code"] == "ResourceNotFoundException", (
            f"a refused domain must not exist; DescribeDomain({name!r}) reported {missing!r}"
        )
        assert missing["message"] == f"Domain not found: {name}", (
            f"DescribeDomain({name!r}) must say 'Domain not found: {name}'; got "
            f"{missing['message']!r}"
        )
    listed = {d["DomainName"] for d in osvc.list_domain_names().get("DomainNames", [])}
    assert not listed & {domain_name, direct_domain}, (
        f"ListDomainNames lists a refused domain: {sorted(listed & {domain_name, direct_domain})!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _with_throttle_retry(fn, *, attempts=8, base_delay_s=3.0):
    """Call fn(), retrying ONLY on ThrottlingException (OpenSearch's CreateDomain rate is low)."""
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or i == attempts - 1:
                raise
            time.sleep(base_delay_s * (i + 1))
    raise AssertionError("unreachable")


def _expect_client_error(fn) -> dict[str, Any]:
    """The {code, message, http_status} fn() fails with. RAISES if fn() unexpectedly SUCCEEDS.

    Deliberately not a falsy sentinel on success: a target that accepts what real AWS refuses
    is the strongest signal there is. Throttling is retried, never returned as the answer.
    """
    try:
        ok = _with_throttle_retry(fn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"code": err.get("Code", ""), "message": err.get("Message", ""),
                "http_status": exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")}
    raise AssertionError(f"expected this call to fail, but it succeeded and returned {ok!r}")


def _volume_bounds(limits: dict[str, Any], volume_type: str) -> tuple[int, int]:
    """(MinimumVolumeSize, MaximumVolumeSize) for one EBS sub-type, from DescribeInstanceTypeLimits."""
    storage = limits.get("LimitsByRole", {}).get("data", {}).get("StorageTypes", [])
    for st in storage:
        if st.get("StorageTypeName") == "ebs" and st.get("StorageSubTypeName") == volume_type:
            vals = {lim["LimitName"]: lim.get("LimitValues", []) for lim in st.get("StorageTypeLimits", [])}
            lo, hi = vals.get("MinimumVolumeSize", []), vals.get("MaximumVolumeSize", [])
            assert len(lo) == 1 and len(hi) == 1, f"unexpected {volume_type} limits {vals!r}"
            return int(lo[0]), int(hi[0])
    raise AssertionError(f"DescribeInstanceTypeLimits reports no ebs/{volume_type} storage: {storage!r}")


def _delete_domain_if_present(osvc, name: str) -> None:
    """Teardown: delete a domain by name; absent is the expected case, anything else is a LEAK."""
    try:
        _with_throttle_retry(lambda: osvc.delete_domain(DomainName=name))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"domain {name} teardown failed: {exc}") from exc


def _all_topic_arns(sns) -> set[str]:
    out: set[str] = set()
    for page in sns.get_paginator("list_topics").paginate():
        out |= {t["TopicArn"] for t in page.get("Topics", [])}
    return out


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _stack_events(cfn, name: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _one_event(events: list[dict[str, Any]], logical_id: str, status: str) -> dict[str, Any]:
    """The single event for one logical id reaching `status`; asserts there is exactly one."""
    hits = [e for e in events
            if e.get("LogicalResourceId") == logical_id and e.get("ResourceStatus") == status]
    assert len(hits) == 1, (
        f"expected exactly one {status} event for {logical_id!r}, found {len(hits)}; events were "
        f"{[(e.get('LogicalResourceId'), e.get('ResourceStatus')) for e in events]!r}"
    )
    return hits[0]


def _first_event(events: list[dict[str, Any]], logical_id: str, status: str) -> dict[str, Any]:
    """The earliest event for one logical id reaching `status` (IN_PROGRESS repeats legitimately)."""
    hits = [e for e in events
            if e.get("LogicalResourceId") == logical_id and e.get("ResourceStatus") == status]
    assert hits, (
        f"no {status} event for {logical_id!r}; events were "
        f"{[(e.get('LogicalResourceId'), e.get('ResourceStatus')) for e in events]!r}"
    )
    return hits[0]


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; teardown, so a failure PRINTS rather than raises."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
        final = _poll_until(lambda: _stack_status(cfn, name),
                            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                            timeout_s=timeout_s, interval_s=5.0,
                            description=f"delete stack {name}")
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


def _create_stack_and_wait(ctx, template: str, *, stack_name: str, parameters: dict[str, str],
                           timeout_s=900.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted.

    A CREATE that FAILS is the behaviour under test, so the caller asserts the terminal status
    CloudFormation itself reached. delete_stack is registered immediately after create_stack.
    """
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Tags=_tags_kv(),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()])
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name, timeout_s=timeout_s))
    status = _poll_until(lambda: _stack_status(cfn, stack_name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {stack_name}")
    return stack_name, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
