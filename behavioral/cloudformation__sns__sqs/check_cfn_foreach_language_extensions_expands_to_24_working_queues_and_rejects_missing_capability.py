"""cfn-foreach-language-extensions-expands-to-24-working-queues-and-rejects-missing-capability."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "cfn-foreach-language-extensions-expands-to-24-working-queues-and-rejects-missing-capability"
)

GROUP = "deploy_intrinsics"

SERVICES = ["cloudformation", "sns", "sqs"]

SLOTS = [chr(ord("a") + i) for i in range(24)]

# Fn::ForEach needs the transform, and the transform needs YAML to stay readable, so this is the
# one template here that is not built from a dict.
_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::LanguageExtensions
Parameters:
  Prefix:
    Type: String
  Ids:
    Type: CommaDelimitedList
    Default: {slots}
Resources:
  'Fn::ForEach::Fanned':
    - Slot
    - !Ref Ids
    - 'Q${{Slot}}':
        Type: AWS::SQS::Queue
        Properties:
          QueueName: !Sub '${{Prefix}}-${{Slot}}'
          VisibilityTimeout: 30
          Tags:
            - Key: 'sim2real:slot'
              Value: !Ref Slot
            - Key: 'sim2real'
              Value: '{check}'
  Sentinel:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Sub '${{Prefix}}-sentinel'
Outputs:
  'Fn::ForEach::Urls':
    - Slot
    - !Ref Ids
    - 'Url${{Slot}}':
        Value: !Ref
          'Fn::Sub': 'Q${{Slot}}'
"""

VISIBILITY_TIMEOUT = "30"


def _template() -> str:
    """One loop block over 24 slots, plus one non-loop Sentinel resource.

    Sentinel is a resource the loop did not generate, so an over-broad expansion is named.
    """
    return _TEMPLATE.format(slots=",".join(SLOTS), check=CHECK)


def _error(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) fn() raises. AssertionError if the call SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("call unexpectedly succeeded; expected it to raise a ClientError")


def _stack_resources(cfn, stack: str) -> list[dict[str, Any]]:
    """Every resource CloudFormation records for a stack, paginated."""
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.list_stack_resources(**kwargs)
        out.extend(page.get("StackResourceSummaries", []))
        token = page.get("NextToken")
        if not token:
            return out


def _queue_urls(sqs, prefix: str) -> list[str]:
    """Every queue in the account whose name starts with prefix, paginated.

    Account-wide because the stack's own record cannot show 24 distinct queues rather than aliases.
    """
    urls: list[str] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"QueueNamePrefix": prefix, "MaxResults": 1000}
        if token:
            kwargs["NextToken"] = token
        page = sqs.list_queues(**kwargs)
        urls.extend(page.get("QueueUrls", []))
        token = page.get("NextToken")
        if not token:
            return urls


def _poll_until(probe, predicate, what: str, timeout_s=1200.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not observed within {timeout_s}s (last observation: {last!r})")


def _wait_stack_status(cfn, stack: str, targets: set[str], timeout_s=1200.0) -> dict[str, Any]:
    def probe():
        try:
            return cfn.describe_stacks(StackName=stack)["Stacks"][0]
        except ClientError:
            return None

    return _poll_until(
        probe,
        lambda s: s is not None and s.get("StackStatus") in targets,
        f"stack {stack!r} reaching one of {sorted(targets)}",
        timeout_s=timeout_s,
    )


def _as_text(template_body) -> str:
    """GetTemplate returns the Original stage as the submitted YAML string and the Processed stage
    as a parsed mapping; normalise both to text so one containment test reads either."""
    if isinstance(template_body, str):
        return template_body
    return json.dumps(template_body)


@tags("axis:rejection", "cap:c3", "cap:c5", "concern:deploy", "concern:representation",
      "concern:e2e", "concern:negative-classes", "plane:control", "plane:data",
      "dp:api")
def run(ctx) -> None:
    """Fn::ForEach under AWS::LanguageExtensions expands into exactly 24 distinct, working queues
    and nothing else, the Original and Processed GetTemplate stages differ, and the same template
    without CAPABILITY_AUTO_EXPAND is refused without creating a stack or queue.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    prefix = ctx.unique_name("sim2real-behav-cfn-fe-")
    name = f"{prefix}-stk"
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=_template(),
        Parameters=[{"ParameterKey": "Prefix", "ParameterValue": prefix}],
        Capabilities=["CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))

    stack = _wait_stack_status(
        cfn, stack_id,
        {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the Fn::ForEach stack ended {stack['StackStatus']!r}: "
        f"{stack.get('StackStatusReason')!r}"
    )

    resources = _stack_resources(cfn, stack_id)
    ids = {r["LogicalResourceId"] for r in resources}
    expected_ids = {f"Q{s}" for s in SLOTS} | {"Sentinel"}
    # 1. exactly the generated ids plus the sentinel: no Fn::ForEach pseudo-resource in the graph
    assert ids == expected_ids, (
        f"stack records logical ids {sorted(ids)!r}; expected {sorted(expected_ids)!r} "
        f"(missing {sorted(expected_ids - ids)!r}, unexpected {sorted(ids - expected_ids)!r})"
    )
    # 2. asserted separately so a superset is named as a count, not just as a set difference
    assert len(resources) == len(SLOTS) + 1, (
        f"the expansion produced {len(resources)} resources, expected {len(SLOTS) + 1}"
    )
    # 3. every generated resource is a real queue that finished creating
    by_id = {r["LogicalResourceId"]: r for r in resources}
    for s in SLOTS:
        r = by_id[f"Q{s}"]
        assert r["ResourceType"] == "AWS::SQS::Queue", (
            f"Q{s} has type {r['ResourceType']!r}, expected 'AWS::SQS::Queue'"
        )
        assert r["ResourceStatus"] == "CREATE_COMPLETE", (
            f"Q{s} is {r['ResourceStatus']!r}, expected 'CREATE_COMPLETE'"
        )

    # 4. negative space against the WHOLE ACCOUNT, not just the stack's own record
    urls = _queue_urls(sqs, prefix)
    assert len(urls) == len(SLOTS), (
        f"the account holds {len(urls)} queues with prefix {prefix!r}, expected {len(SLOTS)}: "
        f"{sorted(urls)!r}"
    )
    names = {PurePosixPath(urlparse(u).path).name for u in urls}
    assert names == {f"{prefix}-{s}" for s in SLOTS}, (
        f"the expanded queue names were {sorted(names)!r}, expected "
        f"{sorted(f'{prefix}-{s}' for s in SLOTS)!r}"
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    # 5. the Outputs loop expanded too -- a separate code path from Resources in every engine
    assert set(outputs) == {f"Url{s}" for s in SLOTS}, (
        f"stack outputs were {sorted(outputs)!r}, expected {sorted(f'Url{s}' for s in SLOTS)!r}"
    )

    # 6/7/8. 24 concurrent round trips, plus the properties and tags the loop body substituted
    def exercise(slot: str) -> tuple[str, str, str, str]:
        url = outputs[f"Url{slot}"]
        marker = f"foreach-{prefix}-{slot}"
        sqs.send_message(QueueUrl=url, MessageBody=marker)
        got = _poll_until(
            lambda: sqs.receive_message(
                QueueUrl=url, WaitTimeSeconds=10, MaxNumberOfMessages=1).get("Messages", []),
            lambda msgs: bool(msgs),
            f"a message on the queue expanded for slot {slot!r}",
            timeout_s=120.0,
            interval_s=1.0,
        )
        sqs.delete_message(QueueUrl=url, ReceiptHandle=got[0]["ReceiptHandle"])
        vis = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]
        tag = (sqs.list_queue_tags(QueueUrl=url).get("Tags") or {}).get("sim2real:slot")
        return got[0]["Body"], marker, vis, tag

    with ThreadPoolExecutor(max_workers=len(SLOTS)) as pool:
        results = dict(zip(SLOTS, pool.map(exercise, SLOTS)))

    for slot, (body, marker, vis, tag) in results.items():
        assert body == marker, (
            f"the queue expanded for slot {slot!r} returned {body!r}, expected {marker!r} -- an "
            f"expansion that produced aliases of one queue shows up here as cross-talk"
        )
        assert vis == VISIBILITY_TIMEOUT, (
            f"the queue for slot {slot!r} reports VisibilityTimeout {vis!r}, expected "
            f"{VISIBILITY_TIMEOUT!r}: the loop body's properties must be substituted, not defaulted"
        )
        assert tag == slot, (
            f"the queue for slot {slot!r} carries tag sim2real:slot={tag!r}; the loop identifier "
            f"must reach a property VALUE, not only the generated logical id"
        )

    # 9. cross-talk negative space: a marker sent to ONE expanded queue reaches no other
    only_first = f"foreach-only-{prefix}-{SLOTS[0]}"
    sqs.send_message(QueueUrl=outputs[f"Url{SLOTS[0]}"], MessageBody=only_first)
    stray = sqs.receive_message(
        QueueUrl=outputs[f"Url{SLOTS[1]}"], WaitTimeSeconds=10, MaxNumberOfMessages=10
    ).get("Messages", [])
    assert stray == [], (
        f"the queue for slot {SLOTS[1]!r} received {[m['Body'] for m in stray]!r} after a message "
        f"was sent only to slot {SLOTS[0]!r}: the 24 queues are not distinct"
    )
    landed = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=outputs[f"Url{SLOTS[0]}"], WaitTimeSeconds=10,
            MaxNumberOfMessages=1).get("Messages", []),
        lambda msgs: bool(msgs),
        f"the single-target message on slot {SLOTS[0]!r}",
        timeout_s=120.0,
        interval_s=1.0,
    )
    assert landed[0]["Body"] == only_first, (
        f"slot {SLOTS[0]!r} returned {landed[0]['Body']!r}, expected {only_first!r}"
    )
    sqs.delete_message(QueueUrl=outputs[f"Url{SLOTS[0]}"],
                       ReceiptHandle=landed[0]["ReceiptHandle"])

    # 10. the two GetTemplate stages are genuinely different documents
    original = _as_text(cfn.get_template(
        StackName=stack_id, TemplateStage="Original")["TemplateBody"])
    processed = _as_text(cfn.get_template(
        StackName=stack_id, TemplateStage="Processed")["TemplateBody"])
    assert "Fn::ForEach" in original, (
        f"the Original stage does not contain the Fn::ForEach node that was submitted: "
        f"{original[:400]!r}"
    )
    assert "Fn::ForEach" not in processed, (
        f"the Processed stage still contains Fn::ForEach, so no expansion pass ran: "
        f"{processed[:400]!r}"
    )
    for s in (SLOTS[0], SLOTS[-1]):
        assert f'"Q{s}"' in processed or f"'Q{s}'" in processed, (
            f"the Processed stage does not name the generated logical id Q{s}: {processed[:400]!r}"
        )
        assert f'"Q{s}"' not in original and f"'Q{s}'" not in original, (
            f"the Original stage already names the generated logical id Q{s}, so the two stages "
            f"are not distinguishable"
        )

    # --- refusal arm: the identical template with no CAPABILITY_AUTO_EXPAND -------------------
    nocap_prefix = ctx.unique_name("sim2real-behav-cfn-fe-nocap-")
    code, message = _error(lambda: cfn.create_stack(
        StackName=f"{nocap_prefix}-stk",
        TemplateBody=_template(),
        Parameters=[{"ParameterKey": "Prefix", "ParameterValue": nocap_prefix}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))
    # 11. the exact capability refusal, not a generic template error
    assert code == "InsufficientCapabilitiesException", (
        f"a transform template submitted without CAPABILITY_AUTO_EXPAND was answered {code!r} "
        f"({message[:200]!r}), expected 'InsufficientCapabilitiesException'"
    )
    assert message == "Requires capabilities : [CAPABILITY_AUTO_EXPAND]", (
        f"the refusal message was {message!r}; expected "
        f"'Requires capabilities : [CAPABILITY_AUTO_EXPAND]'"
    )
    # 12. effect-absent: no stack, and none of the 24 queues
    absent_code, absent_message = _error(
        lambda: cfn.describe_stacks(StackName=f"{nocap_prefix}-stk"))
    assert absent_code == "ValidationError", (
        f"describe_stacks on the refused stack answered {absent_code!r}: the refusal must have "
        f"created no stack"
    )
    assert absent_message == f"Stack with id {nocap_prefix}-stk does not exist", (
        f"describe_stacks on the refused stack answered {absent_message!r}"
    )
    assert _queue_urls(sqs, nocap_prefix) == [], (
        f"the refused stack still created queues: {_queue_urls(sqs, nocap_prefix)!r}"
    )

    # --- teardown with verification: the expansion is tracked well enough to be reversed ------
    cfn.delete_stack(StackName=stack_id)
    deleted = _wait_stack_status(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert deleted["StackStatus"] == "DELETE_COMPLETE", (
        f"delete ended {deleted['StackStatus']!r}: {deleted.get('StackStatusReason')!r}"
    )
    # 13. all 24 expanded queues are gone from the account. DeleteQueue is asynchronous on the SQS
    #     side, so this is a bounded poll for the absence rather than a single read.
    remaining = _poll_until(
        lambda: _queue_urls(sqs, prefix),
        lambda found: found == [],
        f"all {len(SLOTS)} expanded queues disappearing from the account",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert remaining == [], (
        f"{len(remaining)} expanded queues survived DELETE_COMPLETE: {sorted(remaining)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
