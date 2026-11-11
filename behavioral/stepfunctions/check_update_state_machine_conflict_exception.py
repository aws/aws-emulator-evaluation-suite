"""update-state-machine-conflict-exception."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-conflict-exception"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }
        ],
    }
)


def _create_sfn_role(ctx):
    """Create an execution role Step Functions can assume; it is deleted at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for fn in (
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)
    return arn


def _await_role(fn, *, timeout_s=90.0):
    """Call fn(), retrying AccessDeniedException while a new role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    arn = _await_role(lambda: sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type=sm_type,
        tags=[{"key": "sim2real", "value": CHECK}],
    ))["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    import threading
    results = [None] * len(fns)
    resolved = set()
    barrier = threading.Barrier(len(fns))

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)

    def _synced(fn):
        def _inner():
            barrier.wait()
            return fn()
        return _inner
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(_synced(fn)): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five concurrent UpdateStateMachine(publish=True) calls on one state machine resolve safely: at
    least one succeeds, every failure is ConflictException, and the machine ends ACTIVE with the
    revisionId and definition of one racer that succeeded."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"v": 0}))

    def racer(n):
        def _call():
            resp = sfn.update_state_machine(
                stateMachineArn=arn, definition=json.dumps(_asl_pass({"v": n})), publish=True
            )
            return {"n": n, "revisionId": resp.get("revisionId")}
        return _call

    results = _run_concurrent([racer(n) for n in range(1, 6)])
    successes = [r for r in results if not isinstance(r, BaseException)]

    assert successes, f"at least one concurrent UpdateStateMachine(publish=True) must succeed: {results}"
    bad_codes = [c for c in _concurrent_error_codes(results) if c != "ConflictException"]
    assert not bad_codes, f"every failed racer must be ConflictException specifically, got: {bad_codes}"

    # The state machine must converge to ACTIVE with a revisionId and definition that match
    # exactly ONE of the racers that actually succeeded — never a value nobody reported.
    success_revisions = {r["revisionId"] for r in successes}
    success_ns = {r["n"] for r in successes}
    desc = sfn.describe_state_machine(stateMachineArn=arn)
    assert desc["status"] == "ACTIVE", f"expected ACTIVE after concurrent updates, got {desc['status']!r}"
    assert desc.get("revisionId") in success_revisions, (
        f"final revisionId {desc.get('revisionId')!r} must be one a racer actually reported "
        f"succeeding with, got success set {success_revisions!r}"
    )
    final_n = json.loads(desc["definition"])["States"]["P"].get("Result", {}).get("v")
    assert final_n in success_ns, (
        f"final definition carries v={final_n!r}, which must be one of the racers that "
        f"actually succeeded {success_ns!r} — never a corrupted or unattempted value"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
