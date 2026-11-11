"""create-stack-with-a-role-cloudformation-cannot-assume-is-rejected-and-audited."""

# AWS behaviour this check relies on:
#   M1  CreateStack with a RoleARN CloudFormation cannot assume fails ValidationError (HTTP 400),
#       message "Role <arn> is invalid or cannot be assumed". A freshly created role whose trust
#       DOES name cloudformation.amazonaws.com fails the same way for ~10 s (IAM propagation), which
#       is why the refusal is only asserted AFTER a sibling role created later has been accepted.
#   M2  CloudTrail records the refusal with errorCode "ValidationException" (not the SDK's
#       "ValidationError"), the SDK's errorMessage, null requestParameters/responseElements, and
#       requestID equal to the SDK's RequestId.
#   M3  DescribeStacks on a never-created name fails ValidationError "Stack with id <name> does not
#       exist"; GetQueueUrl on an absent queue fails AWS.SimpleQueueService.NonExistentQueue.

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stack-with-a-role-cloudformation-cannot-assume-is-rejected-and-audited"
GROUP = "audit-trail"
SERVICES = ["cloudformation", "cloudtrail"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 600.0  # upper side of the CloudTrail poll
_STACK_BUDGET_S = 420.0  # one stack transition reaching *_COMPLETE
_ROLE_PROPAGATION_BUDGET_S = 120.0  # M1
_CLOCK_SKEW_S = 120.0
_STACK_POLL_S = 1.0
_INDEX_POLL_S = 2.0
_PAGE_CEILING = 60
_REFUSALS = 3  # the untrusted role must be refused this many times, AFTER the barrier

_CFN_SOURCE = "cloudformation.amazonaws.com"


def _error(fn):
    """Return (code, message, request_id, http_status) of the ClientError `fn` raises.

    Raises if `fn` SUCCEEDS, carrying the response so the caller can still tear it down.
    """
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        meta = exc.response.get("ResponseMetadata", {})
        return err.get("Code"), err.get("Message"), meta.get("RequestId"), meta.get("HTTPStatusCode")
    raise _Accepted(resp)


class _Accepted(AssertionError):
    def __init__(self, resp):
        super().__init__(f"expected the call to be rejected, but it succeeded: {resp!r}")
        self.resp = resp


def _template(queue_name):
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}}
            },
        }
    )


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _queue_policy(partition, region, account_id, queue_name):
    return json.dumps(
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
                    "Resource": f"arn:{partition}:sqs:{region}:{account_id}:{queue_name}",
                }
            ],
        }
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stack(ctx, cfn, stack_id, want, budget_s=_STACK_BUDGET_S):
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.monotonic() + budget_s
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
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} to reach {want!r}: the run budget ended first; not graded"
                )
            raise AssertionError(
                f"stack {stack_id} still {status!r} after {budget_s:.0f}s; expected {want!r}"
            )
        time.sleep(_STACK_POLL_S)


# The whole cleanup chain has a short shared budget, so each stack's cleanup only issues DeleteStack
# and one settle net waits for all of them; a role still needed by a stack is kept (and named in the
# raised failure) so CloudFormation can finish on its own.
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
        raise RuntimeError(
            f"stacks still deleting after {_TEARDOWN_SETTLE_S:.0f}s: {pending!r}"
        )
    for name in queue_names:
        _delete_queue_if_present(sqs, name)


def _delete_queue_if_present(sqs, queue_name):
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


def _create_stack_with_role(cfn, ctx, **kw):
    """CreateStack, retrying ONLY the not-yet-assumable-role refusal (M1), bounded, then raising."""
    deadline = time.monotonic() + _budget_s(ctx, _ROLE_PROPAGATION_BUDGET_S)
    while True:
        try:
            return cfn.create_stack(**kw)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "ValidationError"
                or err.get("Message") != f"Role {kw.get('RoleARN')} is invalid or cannot be assumed"
                or time.monotonic() >= deadline
            ):
                if (
                    err.get("Code") == "ValidationError"
                    and err.get("Message") == f"Role {kw.get('RoleARN')} is invalid or cannot be assumed"
                    and _budget_spent(ctx)
                ):
                    raise TimeoutError(
                        "CloudFormation to accept the new role: the run budget ended first; not graded"
                    ) from exc
                raise AssertionError(
                    f"CreateStack with RoleARN {kw.get('RoleARN')!r} did not succeed within "
                    f"{_ROLE_PROPAGATION_BUDGET_S:.0f}s; last error {err!r}"
                ) from exc
            time.sleep(2.0)


def _lookup_all(ct, attr_key, attr_value, start):
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


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CreateStack with a role whose trust omits CloudFormation is refused, creates nothing and is
    audited as ValidationException with the SDK's message; repairing only the trust lets it through.
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
    bad_role = f"sim2real-xsvc-cfnbad-{nonce}"
    good_role = f"sim2real-xsvc-cfngood-{nonce}"
    bad_stack = f"sim2real-xsvc-stkbad-{nonce}"
    good_stack = f"sim2real-xsvc-stkgood-{nonce}"
    bad_queue = f"sim2real-xsvc-qbad-{nonce}"
    good_queue = f"sim2real-xsvc-qgood-{nonce}"
    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=_CLOCK_SKEW_S + 60
    )
    tag = [{"Key": "sim2real", "Value": CHECK[:200]}]

    # ---- two roles, identical permissions, differing ONLY in the trusted service -------------
    stacks = []  # every stack id this check creates, appended immediately after its create
    bad_arn = iam.create_role(
        RoleName=bad_role, AssumeRolePolicyDocument=_trust("lambda.amazonaws.com"), Tags=tag
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_when_stacks_gone(cfn, iam, bad_role, stacks))
    iam.put_role_policy(
        RoleName=bad_role,
        PolicyName="sim2real-provision-one-queue",
        PolicyDocument=_queue_policy(partition, ctx.region, account_id, bad_queue),
    )
    good_arn = iam.create_role(
        RoleName=good_role, AssumeRolePolicyDocument=_trust(_CFN_SOURCE), Tags=tag
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_when_stacks_gone(cfn, iam, good_role, stacks))
    iam.put_role_policy(
        RoleName=good_role,
        PolicyName="sim2real-provision-one-queue",
        PolicyDocument=_queue_policy(partition, ctx.region, account_id, good_queue),
    )
    # Registered before any stack, so LIFO runs it after every DeleteStack has been issued.
    ctx.on_cleanup(
        lambda: _settle_stacks_then_reap_queues(cfn, sqs, stacks, [bad_queue, good_queue])
    )

    # ---- positive control, and the barrier: the LATER role is accepted -----------------------
    good = _create_stack_with_role(
        cfn, ctx, StackName=good_stack, TemplateBody=_template(good_queue), RoleARN=good_arn, Tags=tag
    )
    good_id = good["StackId"]
    stacks.append(good_id)
    ctx.on_cleanup(lambda: _issue_stack_delete(cfn, good_id))
    good_rid = good["ResponseMetadata"]["RequestId"]
    _wait_stack(ctx, cfn, good_id, "CREATE_COMPLETE")

    # ---- the one broken thing: the untrusted role is refused, repeatedly ---------------------
    refusals = []
    for i in range(_REFUSALS):
        try:
            refusals.append(
                _error(
                    lambda: cfn.create_stack(
                        StackName=bad_stack,
                        TemplateBody=_template(bad_queue),
                        RoleARN=bad_arn,
                        Tags=tag,
                    )
                )
            )
        except _Accepted as acc:
            stacks.append(acc.resp["StackId"])
            ctx.on_cleanup(lambda sid=acc.resp["StackId"]: _issue_stack_delete(cfn, sid))
            raise AssertionError(
                f"CreateStack with a role trusting only lambda.amazonaws.com was ACCEPTED on "
                f"attempt {i + 1}: {acc.resp!r}"
            ) from None
        if i + 1 < _REFUSALS:
            time.sleep(2.0)
    expected_msg = f"Role {bad_arn} is invalid or cannot be assumed"
    for code, msg, _rid, status in refusals:
        assert code == "ValidationError", (
            f"untrusted RoleARN: expected error code 'ValidationError', actual {code!r} ({msg!r})"
        )
        assert status == 400, f"untrusted RoleARN: expected HTTP 400, actual {status!r}"
        assert msg == expected_msg, (
            f"untrusted RoleARN: expected message {expected_msg!r}, actual {msg!r}"
        )

    # ---- effect absent: no stack under that name, no queue -----------------------------------
    code, msg, _, _ = _error(lambda: cfn.describe_stacks(StackName=bad_stack))
    assert code == "ValidationError" and msg == f"Stack with id {bad_stack} does not exist", (
        f"a refused CreateStack left something behind: DescribeStacks({bad_stack!r}) gave "
        f"{code!r} {msg!r}, expected ValidationError 'Stack with id {bad_stack} does not exist'"
    )
    code, msg, _, _ = _error(lambda: sqs.get_queue_url(QueueName=bad_queue))
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"a refused CreateStack provisioned its queue: GetQueueUrl({bad_queue!r}) gave {code!r}, "
        "expected 'AWS.SimpleQueueService.NonExistentQueue'"
    )
    assert msg == "The specified queue does not exist.", (
        f"GetQueueUrl({bad_queue!r}) refused with an unexpected message: {msg!r}"
    )

    # ---- repair ONLY the trust, and the same stack name goes through -------------------------
    iam.update_assume_role_policy(RoleName=bad_role, PolicyDocument=_trust(_CFN_SOURCE))
    repaired = _create_stack_with_role(
        cfn, ctx, StackName=bad_stack, TemplateBody=_template(bad_queue), RoleARN=bad_arn, Tags=tag
    )
    repaired_id = repaired["StackId"]
    stacks.append(repaired_id)
    ctx.on_cleanup(lambda: _issue_stack_delete(cfn, repaired_id))
    repaired_rid = repaired["ResponseMetadata"]["RequestId"]
    _wait_stack(ctx, cfn, repaired_id, "CREATE_COMPLETE")
    repaired_url = sqs.get_queue_url(QueueName=bad_queue)["QueueUrl"]
    assert repaired_url.rstrip("/").split("/")[-1] == bad_queue, (
        f"after repairing the trust the queue {bad_queue!r} resolves to {repaired_url!r}"
    )
    last_call = time.time()

    # Tear both stacks down inside the check's own budget: both deletes issued first, then waited,
    # so the cost is the slower of the two rather than their sum.
    for sid in (repaired_id, good_id):
        cfn.delete_stack(StackName=sid)
    for sid in (repaired_id, good_id):
        _wait_stack(ctx, cfn, sid, "DELETE_COMPLETE")

    # ---- CloudTrail: every refusal, the control and the repair, each pinned by requestID -------
    want = {f"refusal-{i + 1}": r[2] for i, r in enumerate(refusals)}
    want["control"] = good_rid
    want["repaired"] = repaired_rid
    found = {}
    index_budget_s = _budget_s(ctx, _INDEX_BUDGET_S)
    deadline = time.monotonic() + index_budget_s
    while True:
        by_rid = {
            r.get("requestID"): r for r in _lookup_all(ct, "EventSource", _CFN_SOURCE, window_start)
        }
        found = {label: by_rid[rid] for label, rid in want.items() if rid in by_rid}
        if len(found) == len(want):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    "CloudTrail to index this check's CreateStack records: the run budget ended "
                    "first; not graded"
                )
            raise AssertionError(
                f"{DATAPLANE_MARKER}: CloudTrail event history lagged beyond the "
                f"{index_budget_s:.0f}s bound: missing {sorted(set(want) - set(found))!r}; "
                f"measured lag since the last call {time.time() - last_call:.0f}s"
            )
        time.sleep(_INDEX_POLL_S)
    print(f"[create-stack-untrusted-role] all records indexed {time.time() - last_call:.0f}s after the last call")

    for i, (_code, sdk_msg, _rid, _status) in enumerate(refusals):
        rec = found[f"refusal-{i + 1}"]
        assert rec.get("eventSource") == _CFN_SOURCE and rec.get("eventName") == "CreateStack", (
            f"refusal {i + 1}: expected {_CFN_SOURCE!r}/CreateStack, actual "
            f"{rec.get('eventSource')!r}/{rec.get('eventName')!r}"
        )
        assert rec.get("errorCode") == "ValidationException", (
            f"refusal {i + 1}: CloudTrail errorCode expected 'ValidationException' (the SDK saw "
            f"'ValidationError'), actual {rec.get('errorCode')!r}"
        )
        assert rec.get("errorMessage") == sdk_msg, (
            f"refusal {i + 1}: audited errorMessage expected the caller's {sdk_msg!r}, actual "
            f"{rec.get('errorMessage')!r}"
        )
        assert rec.get("responseElements") is None, (
            f"refusal {i + 1}: a refused CreateStack minted no stack, so responseElements must be "
            f"null; actual {rec.get('responseElements')!r}"
        )
        assert (rec.get("userIdentity") or {}).get("arn") == caller_arn, (
            f"refusal {i + 1}: userIdentity.arn expected {caller_arn!r}, actual "
            f"{(rec.get('userIdentity') or {}).get('arn')!r}"
        )
    for label, sid, role in (("control", good_id, good_arn), ("repaired", repaired_id, bad_arn)):
        rec = found[label]
        assert rec.get("errorCode") is None, (
            f"{label}: an accepted CreateStack must carry no errorCode, actual "
            f"{rec.get('errorCode')!r}"
        )
        got = (rec.get("responseElements") or {}).get("stackId")
        assert got == sid, f"{label}: responseElements.stackId expected {sid!r}, actual {got!r}"
        got_role = (rec.get("requestParameters") or {}).get("roleARN")
        assert got_role == role, (
            f"{label}: requestParameters.roleARN expected {role!r}, actual {got_role!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
