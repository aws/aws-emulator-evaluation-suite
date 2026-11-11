"""choice-jsonata-assign-is-scoped-to-the-selected-rule."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-jsonata-assign-is-scoped-to-the-selected-rule"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _execution_role(ctx):
    """A throwaway execution role, so the check assumes no pre-existing estate."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-choice-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-choice: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "choice"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    # IAM propagation exposes no condition to poll; the bounded AccessDeniedException retry in
    # _create_state_machine is what makes this correct, and this sleep only makes it cheaper.
    time.sleep(2)
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-choice-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "choice"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_execution(ctx, sm_arn, input_data, *, timeout_s=60):
    """Start one execution, wait for a terminal status, return (describe, entered_state_names)."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-choice-ex-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            break
        time.sleep(0.5)
    else:
        raise AssertionError(
            f"execution for input {input_data!r} never reached a terminal status within "
            f"{timeout_s}s; last describe was {desc!r}"
        )
    return desc, _entered_states(ctx, exec_arn)


def _entered_states(ctx, exec_arn):
    """Every state name the execution ENTERED, in order, from the paginated history."""
    sfn = ctx.client("stepfunctions")
    events = []
    token = None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            break
    return [
        e["stateEnteredEventDetails"]["name"]
        for e in events
        if "stateEnteredEventDetails" in e
    ]


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


_EVAL_ERROR = "States.QueryEvaluationError"

# Branch targets echo the variable, so the OUTPUT reports which Assign block actually ran.
_TARGETS = {
    "First": {"Type": "Pass", "Output": {"branch": "first", "tag": "{% $tag %}"}, "End": True},
    "Second": {"Type": "Pass", "Output": {"branch": "second", "tag": "{% $tag %}"}, "End": True},
    "Fallback": {
        "Type": "Pass",
        "Output": {"branch": "fallback", "tag": "{% $tag %}"},
        "End": True,
    },
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """In JSONata mode a Choice runs only the selected rule's Assign (first match wins), and the
    state-level Assign only on Default; without per-rule Assigns, matched branches fail with
    States.QueryEvaluationError on the undefined variable while the Default path still succeeds."""
    role_arn = _execution_role(ctx)

    def definition(*, per_rule_assign):
        first = {"Condition": "{% $states.input.n > 10 %}", "Next": "First"}
        second = {"Condition": "{% $states.input.n > 0 %}", "Next": "Second"}
        if per_rule_assign:
            first["Assign"] = {"tag": "{% 'from-first-rule' %}"}
            second["Assign"] = {"tag": "{% 'from-second-rule' %}"}
        return {
            "QueryLanguage": "JSONata",
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    # State-level Assign, present in BOTH machines.
                    "Assign": {"tag": "{% 'from-state-level' %}"},
                    "Choices": [first, second],
                    "Default": "Fallback",
                },
                **_TARGETS,
            },
        }

    scoped_arn = _create_state_machine(ctx, definition(per_rule_assign=True), role_arn)

    cases = [
        (
            {"n": 50},
            "first",
            "First",
            "from-first-rule",
            "n=50 satisfies BOTH Conditions; the first rule must win, and its own Assign -- not "
            "the second rule's and not the state-level one -- must be the value that reaches the "
            "branch target",
        ),
        (
            {"n": 5},
            "second",
            "Second",
            "from-second-rule",
            "n=5 satisfies only the second Condition, so the second rule's Assign runs; a "
            "variable of 'from-first-rule' here would mean a non-selected rule's Assign was "
            "applied",
        ),
        (
            {"n": -1},
            "fallback",
            "Fallback",
            "from-state-level",
            "no Condition is satisfied, so the Default is taken and the STATE-level Assign is "
            "the one that applies",
        ),
    ]

    for input_data, branch, state, expected_tag, why in cases:
        desc, entered = _run_execution(ctx, scoped_arn, input_data)
        assert desc["status"] == "SUCCEEDED", (
            f"input {input_data!r} must succeed; a failure means the variable the target echoes "
            f"was never assigned. Got status={desc.get('status')} error={desc.get('error')!r} "
            f"cause={desc.get('cause')!r}"
        )
        assert _output(desc) == {"branch": branch, "tag": expected_tag}, (
            f"input {input_data!r} produced {_output(desc)!r}, expected "
            f"{{'branch': {branch!r}, 'tag': {expected_tag!r}}} -- {why}"
        )
        assert entered == ["Route", state], (
            f"input {input_data!r} must enter ['Route', {state!r}]; history entered "
            f"{entered!r} -- {why}"
        )

    # Break exactly one thing: drop the per-rule Assign blocks, leaving the state-level one.
    state_only_arn = _create_state_machine(ctx, definition(per_rule_assign=False), role_arn)

    for input_data, state in [({"n": 50}, "First"), ({"n": 5}, "Second")]:
        desc, entered = _run_execution(ctx, state_only_arn, input_data)
        assert desc["status"] == "FAILED", (
            f"with only a state-level Assign, a MATCHED rule must leave $tag undefined and the "
            f"execution must fail; input {input_data!r} gave status={desc.get('status')} "
            f"output={desc.get('output')!r} -- a success here means the state-level Assign was "
            f"wrongly applied to a matched branch"
        )
        assert desc.get("error") == _EVAL_ERROR, (
            f"expected {_EVAL_ERROR!r} when the branch target echoes an unassigned variable, got "
            f"{desc.get('error')!r} (cause={desc.get('cause')!r})"
        )
        cause = desc.get("cause") or ""
        assert "returned nothing (undefined)" in cause, (
            f"the cause must say the $tag expression resolved to nothing, which is the evidence "
            f"that the state-level Assign did not run on this path; got {cause!r}"
        )
        assert f"executing the state '{state}'" in cause, (
            f"the failure must be attributed to the branch target {state!r} that echoed the "
            f"variable, not to the Choice state; got {cause!r}"
        )
        assert desc.get("output") is None, (
            f"a failed execution must carry no output, got {desc.get('output')!r}"
        )
        # The routing itself was still correct -- the rule was selected, it just assigned nothing.
        assert entered == ["Route", state], (
            f"the Choice must still have selected {state!r}; history entered {entered!r}"
        )

    # Positive control on the SAME machine: the Default path still works, so the failures above
    # are the scoping rule rather than a broken state machine or an unusable Assign expression.
    desc, entered = _run_execution(ctx, state_only_arn, {"n": -1})
    assert desc["status"] == "SUCCEEDED", (
        f"the Default path of the state-level-only machine must still succeed, got "
        f"status={desc.get('status')} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert _output(desc) == {"branch": "fallback", "tag": "from-state-level"}, (
        f"the state-level Assign must apply on the Default path, producing "
        f"{{'branch': 'fallback', 'tag': 'from-state-level'}}; got {_output(desc)!r}. This is "
        f"what makes the matched-path failures attributable to Assign scoping."
    )
    assert entered == ["Route", "Fallback"], (
        f"the Default control must enter ['Route', 'Fallback']; history entered {entered!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
