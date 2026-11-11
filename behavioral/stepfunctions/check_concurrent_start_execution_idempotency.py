"""concurrent-start-execution-idempotency."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-execution-idempotency"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """Create a Step Functions execution role and register its deletion."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    # A role created moments ago may not yet be assumable by Step Functions; retry within a bound.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
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


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent StartExecution calls with the same name and input create exactly one execution;
    each other racer returns the same executionArn or fails ExecutionAlreadyExists.
    """
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"ok": True}))
    exec_name = ctx.unique_name("sim2real-behav-exec-race-")
    input_json = json.dumps({"same": "payload"})
    n = 5

    results = _run_concurrent(
        [lambda: sfn.start_execution(stateMachineArn=arn, name=exec_name, input=input_json) for _ in range(n)]
    )
    successes = [r for r in results if not isinstance(r, BaseException)]
    assert len(successes) >= 1, f"expected at least one racer to succeed, got: {results}"
    exec_arns = {r["executionArn"] for r in successes}
    assert len(exec_arns) == 1, f"expected exactly one distinct executionArn under the race, got: {exec_arns}"

    failures = [r for r in results if isinstance(r, BaseException)]
    (exec_arn,) = exec_arns
    for exc in failures:
        code = exc.response.get("Error", {}).get("Code") if isinstance(exc, ClientError) else None
        assert code == "ExecutionAlreadyExists", (
            f"a losing racer must fail with ExecutionAlreadyExists (never a distinct execution), got: {exc!r}"
        )
        message = exc.response["Error"].get("Message")
        expected = f"Execution Already Exists: '{exec_arn}'"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = sfn.list_executions(stateMachineArn=arn)
    matching = [e for e in listed["executions"] if e["name"] == exec_name]
    assert len(matching) == 1, f"expected exactly one execution named {exec_name!r}, found {matching}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
