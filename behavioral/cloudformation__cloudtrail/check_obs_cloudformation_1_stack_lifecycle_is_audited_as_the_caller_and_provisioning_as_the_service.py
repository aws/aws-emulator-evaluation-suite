"""obs-cloudformation-1-stack-lifecycle-is-audited-as-the-caller-and-provisioning-as-the-service."""


from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cloudformation-1-stack-lifecycle-is-audited-as-the-caller-and-provisioning-as-the-service"
GROUP = "audit-trail"
SERVICES = ["cloudformation", "cloudtrail"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 600.0  # upper side of the CloudTrail poll, measured from the last audited call
_STACK_BUDGET_S = 420.0  # one stack transition (create / update / delete) reaching *_COMPLETE
_ROLE_PROPAGATION_BUDGET_S = 120.0  # a fresh service role is refused for ~10 s (IAM propagation)
_CLOCK_SKEW_S = 120.0  # lower/upper slack on eventTime vs this host's clock
_POLL_START_S = 5.0
_POLL_CAP_S = 30.0
_PAGE_CEILING = 60

_CFN_SOURCE = "cloudformation.amazonaws.com"
_SQS_SOURCE = "sqs.amazonaws.com"
_DUP_MESSAGE = "Stack [{stack_name}] already exists"


def _template(queue_name, visibility_timeout):
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": queue_name,
                        "VisibilityTimeout": visibility_timeout,
                    },
                }
            },
        }
    )


def _wait_stack(cfn, stack_id, want, budget_s=_STACK_BUDGET_S):
    """Poll DescribeStacks (by StackId, which survives deletion) until `want`; raise on any terminal
    status that is not `want`, quoting the status reason."""
    deadline = time.monotonic() + budget_s
    delay = _POLL_START_S
    while True:
        st = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = st["StackStatus"]
        if status == want:
            return st
        if not status.endswith("_IN_PROGRESS"):
            raise AssertionError(
                f"stack {stack_id} reached {status!r} instead of {want!r}: "
                f"{st.get('StackStatusReason')!r}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_id} still {status!r} after {budget_s:.0f}s; expected {want!r}"
            )
        time.sleep(delay)
        delay = min(delay * 1.5, _POLL_CAP_S)


# The cleanup chain has a short overall budget, so each stack's cleanup only issues DeleteStack and
# one settle net waits for all of them together. A role is deleted only once no stack still needs
# it to finish deleting; otherwise it is kept and named in the raised failure.
_TEARDOWN_SETTLE_S = 40.0


def _issue_stack_delete(cfn, stack_id):
    try:
        cfn.delete_stack(StackName=stack_id)
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"DeleteStack {stack_id} could not be issued: {exc!r}") from exc


def _stack_gone(cfn, stack_id):
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ValidationError":
            return True
        raise
    return status == "DELETE_COMPLETE"


def _settle_stacks_then_reap_queues(cfn, sqs, stacks, queue_names):
    deadline = time.monotonic() + _TEARDOWN_SETTLE_S
    pending = [s for s in stacks if not _stack_gone(cfn, s)]
    while pending and time.monotonic() < deadline:
        time.sleep(3.0)
        pending = [s for s in pending if not _stack_gone(cfn, s)]
    if pending:
        # Do not race CloudFormation's own DeleteQueue; it finishes the job with the role kept.
        raise RuntimeError(
            f"stacks still deleting after {_TEARDOWN_SETTLE_S:.0f}s: {pending!r}"
        )
    for name in queue_names:
        _delete_queue_if_present(sqs, name)


def _delete_queue_if_present(sqs, queue_name):
    """Safety net for a queue a stack provisioned, in case the stack delete did not remove it."""
    try:
        url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    except ClientError:
        return
    sqs.delete_queue(QueueUrl=url)


def _delete_role_when_stacks_gone(cfn, iam, role_name, stacks):
    live = [s for s in stacks if not _stack_gone(cfn, s)]
    if live:
        raise RuntimeError(
            f"IAM role {role_name} kept: stacks {live!r} still need it to finish deleting"
        )
    _delete_role_completely(iam, role_name)


def _delete_role_completely(iam, role_name):
    try:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for name in names:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)


def _create_stack_with_role(cfn, **kw):
    """CreateStack, retrying only the not-yet-assumable-role refusal, bounded, then raising."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        before = time.time()
        try:
            resp = cfn.create_stack(**kw)
            return resp, before, time.time()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "ValidationError"
                or err.get("Message") != f"Role {kw.get('RoleARN')} is invalid or cannot be assumed"
                or time.monotonic() >= deadline
            ):
                raise AssertionError(
                    f"CreateStack with RoleARN {kw.get('RoleARN')!r} did not succeed within "
                    f"{_ROLE_PROPAGATION_BUDGET_S:.0f}s; last error {err!r}"
                ) from exc
            time.sleep(5.0)


def _lookup_all(ct, attr_key, attr_value, start):
    """Page LookupEvents to exhaustion (bounded), riding out LookupEvents' 2-TPS throttle."""
    out = []
    kw = {
        "LookupAttributes": [{"AttributeKey": attr_key, "AttributeValue": attr_value}],
        "StartTime": start,
    }
    for _ in range(_PAGE_CEILING):
        for attempt in range(6):
            try:
                resp = ct.lookup_events(**kw)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or attempt == 5:
                    raise
                time.sleep(2.0 * (attempt + 1))
        out.extend(json.loads(e["CloudTrailEvent"]) for e in resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
        kw["NextToken"] = nxt
    raise AssertionError(
        f"LookupEvents {attr_key}={attr_value} paged past {_PAGE_CEILING} pages; refusing to "
        "assert membership in a truncated result"
    )


def _event_epoch(raw):
    return datetime.datetime.strptime(raw["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    ).timestamp()


def _assert_in_window(label, raw, before, after):
    """The two-sided time bound: the record's eventTime lies inside the bracket of its own call."""
    t = _event_epoch(raw)
    lo, hi = before - _CLOCK_SKEW_S, after + _CLOCK_SKEW_S
    assert lo <= t <= hi, (
        f"{label}: eventTime {raw['eventTime']!r} is outside the call's own bracket "
        f"[{lo:.0f}, {hi:.0f}] (call issued between {before:.0f} and {after:.0f}, "
        f"skew allowance {_CLOCK_SKEW_S:.0f}s)"
    )


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A stack's lifecycle calls (including a refused duplicate CreateStack) are audited in
    CloudTrail as the caller, and the queue it provisions is audited as CloudFormation acting
    through the service role.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-api-logging-cloudtrail.html
    """
    cfn = ctx.client("cloudformation")
    ct = ctx.client("cloudtrail")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    ident = ctx.client("sts").get_caller_identity()
    caller_arn = ident["Arn"]
    account_id = ident["Account"]
    partition = caller_arn.split(":")[1]

    nonce = ctx.unique_name("")
    role_name = f"sim2real-xsvc-cfnrole-{nonce}"
    stack_name = f"sim2real-xsvc-stk-{nonce}"
    queue_name = f"sim2real-xsvc-q-{nonce}"
    # LookupEvents' lower bound: everything this check audits happens after this instant.
    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=_CLOCK_SKEW_S + 60
    )

    # ---- the service role CloudFormation will act through ------------------------------------
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": _CFN_SOURCE},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    stacks = []  # every stack id this check creates, appended immediately after its create
    ctx.on_cleanup(lambda: _delete_role_when_stacks_gone(cfn, iam, role_name, stacks))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-provision-one-queue",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "sqs:CreateQueue",
                            "sqs:DeleteQueue",
                            "sqs:GetQueueAttributes",
                            "sqs:SetQueueAttributes",
                            "sqs:GetQueueUrl",
                            "sqs:TagQueue",
                            "sqs:UntagQueue",
                            "sqs:ListQueueTags",
                        ],
                        "Resource": f"arn:{partition}:sqs:{ctx.region}:{account_id}:{queue_name}",
                    }
                ],
            }
        ),
    )
    # Registered BEFORE the stack so LIFO runs it AFTER the DeleteStack is issued.
    ctx.on_cleanup(lambda: _settle_stacks_then_reap_queues(cfn, sqs, stacks, [queue_name]))

    # ---- 1. CreateStack, as the caller, passing the service role -----------------------------
    created, c_before, c_after = _create_stack_with_role(
        cfn,
        StackName=stack_name,
        TemplateBody=_template(queue_name, 30),
        RoleARN=role_arn,
        Tags=[{"Key": "sim2real", "Value": "obs-cloudformation-1"}],
    )
    stack_id = created["StackId"]
    stacks.append(stack_id)
    ctx.on_cleanup(lambda: _issue_stack_delete(cfn, stack_id))
    create_rid = created["ResponseMetadata"]["RequestId"]
    _wait_stack(cfn, stack_id, "CREATE_COMPLETE")
    create_done = time.time()
    queue_url =cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Queue")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    assert queue_url.rstrip("/").split("/")[-1] == queue_name, (
        f"the stack's queue physical id {queue_url!r} does not name the queue {queue_name!r}"
    )

    # ---- 2. duplicate CreateStack while the stack is live: refused, nothing replaced ----------
    d_before = time.time()
    try:
        dup = cfn.create_stack(
            StackName=stack_name, TemplateBody=_template(queue_name, 30), RoleARN=role_arn
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        meta = exc.response.get("ResponseMetadata", {})
        dup_code, dup_msg = err.get("Code"), err.get("Message")
        dup_rid, dup_status = meta.get("RequestId"), meta.get("HTTPStatusCode")
    else:
        # Wrongly accepted: whatever it made must still be torn down before we fail.
        stacks.append(dup["StackId"])
        ctx.on_cleanup(lambda: _issue_stack_delete(cfn, dup["StackId"]))
        raise AssertionError(
            f"a duplicate CreateStack for live stack {stack_name!r} was ACCEPTED: {dup!r}"
        )
    d_after = time.time()
    assert dup_code == "AlreadyExistsException", (
        f"duplicate CreateStack: expected error code 'AlreadyExistsException', actual {dup_code!r}"
    )
    assert dup_status == 400, f"duplicate CreateStack: expected HTTP 400, actual {dup_status!r}"
    want_dup_msg = _DUP_MESSAGE.format(stack_name=stack_name)
    assert dup_msg == want_dup_msg, (
        f"duplicate CreateStack: expected message {want_dup_msg!r}, actual {dup_msg!r}"
    )
    # Positive control for the refusal: the ORIGINAL stack is untouched -- same id, same status.
    live = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    assert [s["StackId"] for s in live] == [stack_id], (
        f"after the refused duplicate, {stack_name!r} resolves to {[s['StackId'] for s in live]!r}; "
        f"expected exactly the original {stack_id!r}"
    )
    assert live[0]["StackStatus"] == "CREATE_COMPLETE", (
        f"the refused duplicate disturbed the original stack: status {live[0]['StackStatus']!r}"
    )

    # ---- 3. UpdateStack: a real, observable change at SQS ------------------------------------
    u_before = time.time()
    updated = cfn.update_stack(
        StackName=stack_name, TemplateBody=_template(queue_name, 45), RoleARN=role_arn
    )
    u_after = time.time()
    update_rid = updated["ResponseMetadata"]["RequestId"]
    assert updated["StackId"] == stack_id, (
        f"UpdateStack returned StackId {updated['StackId']!r}, expected {stack_id!r}"
    )
    _wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
    vt = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert vt == "45", f"after UpdateStack the queue's VisibilityTimeout is {vt!r}, expected '45'"
    after_update_url = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Queue")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    assert after_update_url == queue_url, (
        f"an in-place VisibilityTimeout update REPLACED the queue: {queue_url!r} -> "
        f"{after_update_url!r}"
    )

    # ---- 4. DeleteStack ----------------------------------------------------------------------
    x_before = time.time()
    deleted = cfn.delete_stack(StackName=stack_name)
    x_after = time.time()
    delete_rid = deleted["ResponseMetadata"]["RequestId"]
    _wait_stack(cfn, stack_id, "DELETE_COMPLETE")

    # ---- 5. CloudTrail: poll under a bounded deadline, with backoff, measuring lag -----------
    want = {
        "CreateStack": create_rid,
        "CreateStack(duplicate)": dup_rid,
        "UpdateStack": update_rid,
        "DeleteStack": delete_rid,
    }
    issued_at = {
        "CreateStack": c_after,
        "CreateStack(duplicate)": d_after,
        "UpdateStack": u_after,
        "DeleteStack": x_after,
        "CreateQueue": c_after,
    }
    found = {}
    seen_at = {}
    queue_records = []
    poll_t0 = time.time()
    deadline = time.monotonic() + _INDEX_BUDGET_S
    delay = _POLL_START_S
    while True:
        by_rid = {r.get("requestID"): r for r in _lookup_all(ct, "EventSource", _CFN_SOURCE, window_start)}
        for label, rid in want.items():
            if label not in found and rid in by_rid:
                found[label] = by_rid[rid]
                seen_at[label] = time.time()
        if "CreateQueue" not in found:
            queue_records = [
                r
                for r in _lookup_all(ct, "EventName", "CreateQueue", window_start)
                if (r.get("requestParameters") or {}).get("queueName") == queue_name
            ]
            if queue_records:
                found["CreateQueue"] = queue_records[0]
                seen_at["CreateQueue"] = time.time()
        if len(found) == len(want) + 1:
            break
        if time.monotonic() >= deadline:
            missing = sorted((set(want) | {"CreateQueue"}) - set(found))
            lag = {k: round(time.time() - issued_at[k]) for k in missing}
            raise AssertionError(
                f"{DATAPLANE_MARKER}: CloudTrail event history lagged beyond the "
                f"{_INDEX_BUDGET_S:.0f}s bound: still missing {missing!r} after polling "
                f"{time.time() - poll_t0:.0f}s; measured lag since each call (s) {lag!r}; "
                f"indexed so far {sorted(found)!r}"
            )
        time.sleep(delay)
        delay = min(delay * 1.5, _POLL_CAP_S)
    lag = {k: round(seen_at[k] - issued_at[k], 1) for k in found}
    print(f"[obs-cloudformation-1] CloudTrail index lag upper bound per record (s): {lag}")

    # ---- 6. the three successful lifecycle records ---------------------------------------------
    brackets = {
        "CreateStack": (c_before, c_after),
        "CreateStack(duplicate)": (d_before, d_after),
        "UpdateStack": (u_before, u_after),
        "DeleteStack": (x_before, x_after),
    }
    for label in ("CreateStack", "UpdateStack", "DeleteStack"):
        rec = found[label]
        assert rec.get("eventSource") == _CFN_SOURCE, (
            f"{label}: eventSource expected {_CFN_SOURCE!r}, actual {rec.get('eventSource')!r}"
        )
        assert rec.get("eventName") == label, (
            f"{label}: eventName expected {label!r}, actual {rec.get('eventName')!r}"
        )
        req = rec.get("requestParameters") or {}
        assert req.get("stackName") == stack_name, (
            f"{label}: requestParameters.stackName expected {stack_name!r}, actual "
            f"{req.get('stackName')!r}"
        )
        who = (rec.get("userIdentity") or {}).get("arn")
        assert who == caller_arn, (
            f"{label}: userIdentity.arn must be the CALLER, not the service role: expected "
            f"{caller_arn!r}, actual {who!r}"
        )
        assert rec.get("errorCode") is None, (
            f"{label}: a successful call must carry no errorCode, actual {rec.get('errorCode')!r}"
        )
        assert rec.get("readOnly") is False, (
            f"{label}: a mutating call must be readOnly=false, actual {rec.get('readOnly')!r}"
        )
        _assert_in_window(label, rec, *brackets[label])
    for label in ("CreateStack", "UpdateStack"):
        rec = found[label]
        got_id = (rec.get("responseElements") or {}).get("stackId")
        assert got_id == stack_id, (
            f"{label}: responseElements.stackId must be the StackId CreateStack returned: "
            f"expected {stack_id!r}, actual {got_id!r}"
        )
        got_role = (rec.get("requestParameters") or {}).get("roleARN")
        assert got_role == role_arn, (
            f"{label}: requestParameters.roleARN expected {role_arn!r}, actual {got_role!r}"
        )
    # DeleteStack has no output shape, so its record's responseElements must be null.
    assert found["DeleteStack"].get("responseElements") is None, (
        "DeleteStack returns no fields, so its record's responseElements must be null; actual "
        f"{found['DeleteStack'].get('responseElements')!r}"
    )

    # ---- 7. the refused duplicate is audited with its error ----------------------------------
    rec = found["CreateStack(duplicate)"]
    assert rec.get("eventSource") == _CFN_SOURCE and rec.get("eventName") == "CreateStack", (
        f"duplicate: expected {_CFN_SOURCE!r}/CreateStack, actual "
        f"{rec.get('eventSource')!r}/{rec.get('eventName')!r}"
    )
    assert rec.get("errorCode") == "AlreadyExistsException", (
        f"duplicate: errorCode expected 'AlreadyExistsException', actual {rec.get('errorCode')!r}"
    )
    assert rec.get("errorMessage") == want_dup_msg, (
        "duplicate: the audited errorMessage must be the message the caller received: expected "
        f"{want_dup_msg!r}, actual {rec.get('errorMessage')!r}"
    )
    assert rec.get("responseElements") is None, (
        "duplicate: a refused CreateStack minted no stack, so responseElements must be null; "
        f"actual {rec.get('responseElements')!r}"
    )
    assert (rec.get("userIdentity") or {}).get("arn") == caller_arn, (
        f"duplicate: userIdentity.arn expected {caller_arn!r}, actual "
        f"{(rec.get('userIdentity') or {}).get('arn')!r}"
    )
    _assert_in_window("CreateStack(duplicate)", rec, *brackets["CreateStack(duplicate)"])

    # ---- 8. the provisioning CreateQueue: CloudFormation, through the role, not the caller -----
    q = found["CreateQueue"]
    qi = q.get("userIdentity") or {}
    assert q.get("eventSource") == _SQS_SOURCE, (
        f"CreateQueue: eventSource expected {_SQS_SOURCE!r}, actual {q.get('eventSource')!r}"
    )
    assert qi.get("invokedBy") == _CFN_SOURCE, (
        "CreateQueue: userIdentity.invokedBy must name CloudFormation as the actor: expected "
        f"{_CFN_SOURCE!r}, actual {qi.get('invokedBy')!r}"
    )
    assert q.get("sourceIPAddress") == _CFN_SOURCE, (
        f"CreateQueue: sourceIPAddress expected {_CFN_SOURCE!r} (a service acting on the caller's "
        f"behalf), actual {q.get('sourceIPAddress')!r}"
    )
    assert qi.get("arn") != caller_arn, (
        f"CreateQueue was attributed to the CALLER {caller_arn!r}; CloudFormation provisioned it"
    )
    assert qi.get("type") == "AssumedRole", (
        f"CreateQueue: userIdentity.type expected 'AssumedRole' (the service role), actual "
        f"{qi.get('type')!r}"
    )
    issuer = ((qi.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
    assert issuer == role_arn, (
        "CreateQueue: the session must be issued by the RoleARN passed to CreateStack: expected "
        f"{role_arn!r}, actual {issuer!r}"
    )
    session_prefix = f"arn:{partition}:sts::{account_id}:assumed-role/{role_name}/"
    assert (qi.get("arn") or "").startswith(session_prefix), (
        f"CreateQueue: userIdentity.arn expected a session of {role_name!r} "
        f"({session_prefix}...), actual {qi.get('arn')!r}"
    )
    q_attrs = (q.get("requestParameters") or {}).get("attributes") or {}
    assert q_attrs.get("VisibilityTimeout") == "30", (
        "CreateQueue: the provisioning call must carry the TEMPLATE's original VisibilityTimeout "
        f"'30', actual {q_attrs.get('VisibilityTimeout')!r}"
    )
    q_url = (q.get("responseElements") or {}).get("queueUrl")
    assert q_url == queue_url, (
        f"CreateQueue: responseElements.queueUrl expected the stack's physical id {queue_url!r}, "
        f"actual {q_url!r}"
    )
    # This check never calls CreateQueue itself: every such record for this queue is CloudFormation's.
    by_caller = [r for r in queue_records if (r.get("userIdentity") or {}).get("arn") == caller_arn]
    assert not by_caller, (
        f"{len(by_caller)} CreateQueue record(s) for {queue_name!r} are attributed to the caller"
    )
    # Provisioning happens between CreateStack returning and the stack reaching CREATE_COMPLETE.
    _assert_in_window("CreateQueue", q, c_before, create_done)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
