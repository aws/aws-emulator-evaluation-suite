"""express-sync-failure-returns-a-result-not-an-error-with-billing-details."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-sync-failure-returns-a-result-not-an-error-with-billing-details"
GROUP = "express_workflows"
SERVICES = ["stepfunctions"]

_FAIL_ERROR = "ExpressSyncBoom"
_FAIL_CAUSE = "deliberate Fail state so the sync response carries a failure verdict"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A synchronous Express execution reports a workflow failure INSIDE a successful
    response (status FAILED + error + cause + billingDetails, no output), never as a client
    error; the Express execution ARN is then refused with InvalidArn by history and stop."""
    sfn = ctx.client("stepfunctions")
    _role_name, role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    marker = ctx.unique_name("sim2real-express-")

    # --- Positive control: the same machine, the same call, a succeeding path -----------
    ok = sfn.start_sync_execution(
        stateMachineArn=sm_arn, input=json.dumps({"mode": "ok", "marker": marker})
    )
    assert ok["status"] == "SUCCEEDED", (
        "the mode=ok synchronous Express execution must report status SUCCEEDED — without "
        "this control the failure assertions below cannot tell a working sync endpoint "
        f"from one that answers FAILED to everything; got {ok['status']!r} "
        f"error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    ok_output = json.loads(ok["output"])
    assert ok_output == {"mode": "ok", "marker": marker, "ok": True}, (
        "the succeeding sync response must return the workflow's output inline; expected "
        f'{{"mode": "ok", "marker": {marker!r}, "ok": True}}, got {ok_output!r}'
    )
    assert ok["stateMachineArn"] == sm_arn, (
        f"the sync response must name the state machine it ran; expected {sm_arn}, got "
        f"{ok.get('stateMachineArn')!r}"
    )
    _assert_billing(ok, "the succeeding")

    # --- The subject: an ASL failure surfaces as a RESULT, not as an exception ----------
    try:
        boom = sfn.start_sync_execution(
            stateMachineArn=sm_arn, input=json.dumps({"mode": "boom", "marker": marker})
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(
            "StartSyncExecution must report a workflow failure inside a successful "
            f"response carrying status=FAILED; it raised {code!r} instead "
            f"({exc.response.get('Error', {}).get('Message')!r}). A target that maps ASL "
            "failures onto client errors breaks every synchronous Express caller."
        ) from exc

    assert boom["status"] == "FAILED", (
        f"the mode=boom synchronous Express execution must report status FAILED (the only "
        f"other legal values are SUCCEEDED and TIMED_OUT); got {boom['status']!r}"
    )
    assert boom["error"] == _FAIL_ERROR, (
        f"the sync response must carry the Fail state's Error name verbatim; expected "
        f"{_FAIL_ERROR!r}, got {boom.get('error')!r}"
    )
    assert boom.get("cause") == _FAIL_CAUSE, (
        f"the sync response must carry the Fail state's Cause verbatim; expected "
        f"{_FAIL_CAUSE!r}, got {boom.get('cause')!r}"
    )
    assert "output" not in boom, (
        "a FAILED synchronous Express execution has no output, so the response must omit "
        f"the field entirely; it carried output={boom.get('output')!r}"
    )
    _assert_billing(boom, "the failing")

    # The failure is billed too — the discriminator against a target that only fills
    # billingDetails on the happy path.
    assert boom["billingDetails"]["billedMemoryUsedInMB"] == ok["billingDetails"][
        "billedMemoryUsedInMB"
    ], (
        "both sync executions ran the same state machine, so the billed memory must "
        f"match; succeeded reported "
        f"{ok['billingDetails']['billedMemoryUsedInMB']}MB and failed reported "
        f"{boom['billingDetails']['billedMemoryUsedInMB']}MB"
    )

    # --- Two-sided clock on the response's own dates -----------------------------------
    for label, resp in (("succeeding", ok), ("failing", boom)):
        span = (resp["stopDate"] - resp["startDate"]).total_seconds()
        assert span >= 0.0, (
            f"the {label} sync response's stopDate must not precede its startDate; "
            f"startDate={resp['startDate']} stopDate={resp['stopDate']}"
        )
        assert span < 60.0, (
            f"the {label} sync response describes a Choice plus one state and must span "
            f"well under 60s; it reported {span:.2f}s"
        )
        billed_s = resp["billingDetails"]["billedDurationInMilliseconds"] / 1000.0
        assert billed_s <= span + 1.0, (
            f"the {label} response's billed duration ({billed_s:.3f}s) must not exceed the "
            f"wall-clock span it itself reports ({span:.3f}s) by more than 1s"
        )

    # --- Express history is not retained in the control plane ---------------------------
    code, message = _error_code(
        lambda: sfn.get_execution_history(executionArn=boom["executionArn"]),
        "GetExecutionHistory on an Express execution ARN",
    )
    assert code == "InvalidArn", (
        "Express execution history is delivered to CloudWatch Logs and is not retained "
        "in the control plane; GetExecutionHistory rejects the Express execution ARN "
        f"outright with InvalidArn rather than ExecutionDoesNotExist; got {code!r}"
    )
    expected_message = "Invalid Arn: 'Resource type not valid in this context: express'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # ...but the standard control plane still refuses to STOP it, for the same reason, so
    # the ARN is genuinely absent from the execution store rather than merely unreadable.
    stop_code, stop_message = _error_code(
        lambda: sfn.stop_execution(executionArn=boom["executionArn"]),
        "StopExecution on a completed Express execution ARN",
    )
    assert stop_code == "InvalidArn", (
        "a mutation against the Express execution ARN must also be refused, proving the "
        f"ARN is absent from the execution store and not just unreadable; got {stop_code!r}"
    )
    expected_stop = "Invalid Arn: 'Resource type not valid in this context: express'"
    assert stop_message == expected_stop, f"expected message {expected_stop!r}, got {stop_message!r}"



_DEFINITION = json.dumps(
    {
        "Comment": "express sync: one success path, one Fail path, chosen by $.mode",
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.mode", "StringEquals": "boom", "Next": "Boom"}
                ],
                "Default": "Ok",
            },
            "Ok": {"Type": "Pass", "Result": True, "ResultPath": "$.ok", "End": True},
            "Boom": {"Type": "Fail", "Error": _FAIL_ERROR, "Cause": _FAIL_CAUSE},
        },
    }
)

_TRUST = json.dumps(
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


def _assert_billing(resp: dict, label: str) -> None:
    billing = resp.get("billingDetails")
    assert isinstance(billing, dict), (
        f"{label} synchronous Express response must carry a billingDetails structure; got "
        f"{billing!r}"
    )
    duration = billing.get("billedDurationInMilliseconds")
    memory = billing.get("billedMemoryUsedInMB")
    assert isinstance(duration, int) and duration > 0, (
        f"{label} response's billedDurationInMilliseconds must be a positive integer — "
        f"the Smithy model defaults it to 0, so a target that omits it reads as 0 here; "
        f"got {duration!r}"
    )
    assert isinstance(memory, int) and memory > 0, (
        f"{label} response's billedMemoryUsedInMB must be a positive integer; got "
        f"{memory!r}"
    )


def _error_code(fn, what: str) -> tuple:
    """The (code, message) fn raises. Raises if fn SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} must be refused, but it succeeded")


def _create_sfn_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnexp-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: express sync failure verdict",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["states:DescribeStateMachine"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """An EXPRESS state machine, bounded-retrying only the AccessDeniedException raised
    while the freshly created role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnexp-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_DEFINITION,
                roleArn=role_arn,
                type="EXPRESS",
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was "
        f"created. Last error: {last}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
