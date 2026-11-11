"""choice-path-comparators-dereference-the-referenced-field."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-path-comparators-dereference-the-referenced-field"
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


_RUNTIME_ERROR = "States.Runtime"
_INVALID_PATH_CAUSE = "The choice state's condition path references an invalid value"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Numeric/Boolean/Timestamp *Path comparators compare against the value at the referenced path:
    moving only that field flips the branch, and removing it fails the execution with
    States.Runtime naming the path, with no output and no branch entered.
    """
    role_arn = _execution_role(ctx)

    def machine(comparator, ref_path):
        return _create_state_machine(
            ctx,
            {
                "StartAt": "Route",
                "States": {
                    "Route": {
                        "Type": "Choice",
                        "Choices": [
                            {"Variable": "$.subject", comparator: ref_path, "Next": "Matched"},
                        ],
                        "Default": "Fallback",
                    },
                    "Matched": {"Type": "Pass", "Result": "matched", "End": True},
                    "Fallback": {"Type": "Pass", "Result": "fell-back", "End": True},
                },
            },
            role_arn,
        )

    cases = [
        # comparator, referenced path, constant subject, referenced value that MATCHES,
        # referenced value that does NOT, and why
        (
            "NumericGreaterThanPath",
            "$.limit",
            50,
            10,
            100,
            "50 > 10 matches and 50 > 100 does not; the subject never moves, so only a real "
            "dereference of $.limit can flip the branch",
        ),
        (
            "BooleanEqualsPath",
            "$.want",
            True,
            True,
            False,
            "true equals the referenced true and differs from the referenced false",
        ),
        (
            "TimestampLessThanPath",
            "$.cutoff",
            "2024-01-01T00:00:00Z",
            "2024-06-01T00:00:00Z",
            "2023-06-01T00:00:00Z",
            "the subject instant is before the later cutoff and not before the earlier one",
        ),
    ]

    for comparator, ref_path, subject, matching_ref, other_ref, why in cases:
        sm_arn = machine(comparator, ref_path)
        ref_key = ref_path.removeprefix("$.")

        # Positive control: the referenced value makes the comparison true.
        desc, entered = _run_execution(
            ctx, sm_arn, {"subject": subject, ref_key: matching_ref}
        )
        assert desc["status"] == "SUCCEEDED", (
            f"{comparator} control must succeed, got status={desc.get('status')} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        assert _output(desc) == "matched", (
            f"{comparator} with subject={subject!r} and {ref_path}={matching_ref!r} must take "
            f"the rule's branch; expected output 'matched', got {_output(desc)!r} -- {why}"
        )
        assert entered == ["Route", "Matched"], (
            f"{comparator} control must enter ['Route', 'Matched'], history entered {entered!r}"
        )

        # Move only the referenced field, so a branch change is attributable to the dereference.
        desc, entered = _run_execution(ctx, sm_arn, {"subject": subject, ref_key: other_ref})
        assert desc["status"] == "SUCCEEDED", (
            f"{comparator} with a non-matching referenced value must still succeed via Default, "
            f"got status={desc.get('status')} error={desc.get('error')!r} "
            f"cause={desc.get('cause')!r}"
        )
        assert _output(desc) == "fell-back", (
            f"{comparator} with subject={subject!r} unchanged and only {ref_path} moved to "
            f"{other_ref!r} must stop matching and fall through to Default; expected output "
            f"'fell-back', got {_output(desc)!r} -- {why}. An identical result for both "
            f"referenced values means the right-hand side was never read."
        )
        assert entered == ["Route", "Fallback"], (
            f"{comparator} with a non-matching referenced value must never enter 'Matched'; "
            f"history entered {entered!r}"
        )

        # Delete only the referenced field: an unresolvable path fails rather than reading false.
        desc, entered = _run_execution(ctx, sm_arn, {"subject": subject})
        assert desc["status"] == "FAILED", (
            f"{comparator} must FAIL the execution when {ref_path} does not resolve, rather "
            f"than treating the rule as false; got status={desc.get('status')} "
            f"output={desc.get('output')!r}"
        )
        assert desc.get("error") == _RUNTIME_ERROR, (
            f"{comparator} with an unresolvable {ref_path} must report {_RUNTIME_ERROR!r}, got "
            f"{desc.get('error')!r} (cause={desc.get('cause')!r})"
        )
        cause = desc.get("cause") or ""
        assert _INVALID_PATH_CAUSE in cause, (
            f"the cause must identify the unresolvable condition path so a caller can tell this "
            f"apart from any other States.Runtime failure; got {cause!r}"
        )
        assert ref_path in cause, (
            f"the cause must name the path that failed to resolve ({ref_path}); got {cause!r}"
        )
        assert desc.get("output") is None, (
            f"a failed execution must carry no output, got {desc.get('output')!r}"
        )
        assert entered == ["Route"], (
            f"an unresolvable {ref_path} must enter the Choice state and stop there -- neither "
            f"'Matched' nor 'Fallback' may be entered; history entered {entered!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
