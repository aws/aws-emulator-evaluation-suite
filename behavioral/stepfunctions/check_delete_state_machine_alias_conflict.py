"""delete-state-machine-alias-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-state-machine-alias-conflict"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, so the
    outcome never rests on an execution role the account happens to carry."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
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


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachineAlias racing DeleteStateMachineAlias on one alias resolves safely: at least one
    call succeeds, the loser fails only with ConflictException or ResourceNotFound, and the alias ends
    deleted (ResourceNotFound with the exact message)."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"v": 1}), _create_sfn_role(ctx))
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    alias_name = ctx.unique_name("sim2real-behav-alias-midupd-")
    sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )
    alias_arn = f"{arn}:{alias_name}"

    results = _run_concurrent(
        [
            lambda: sfn.update_state_machine_alias(
                stateMachineAliasArn=alias_arn, description="mid-update-race"
            ),
            lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn),
        ]
    )

    n_success = _concurrent_successes(results)
    assert n_success >= 1, f"at least one of the racing update/delete calls must succeed: {results}"

    # message varies: which racer loses, and with which of the two codes, is decided by timing
    allowed_codes = {"ConflictException", "ResourceNotFound"}
    bad_codes = [c for c in _concurrent_error_codes(results) if c not in allowed_codes]
    assert not bad_codes, f"racing update/delete must only ever fail with {allowed_codes}, got: {bad_codes}"

    # When the delete lost the race the alias survives; the identical delete is repeated so the
    # terminal state is still observed. Update on an alias mid-delete cannot resurrect it.
    if isinstance(results[1], BaseException):
        sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)
    code, message = _error(lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected = f"Resource not found: '{alias_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
