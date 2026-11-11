"""create-pipeline-cyclic-dependson-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-pipeline-cyclic-dependson-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sagemaker']


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_with_role_retry(fn, *, timeout_s=180.0, interval_s=3.0):
    """Run fn() until it succeeds, retrying only a role-related refusal (IAM propagation is
    eventually consistent) until the deadline; every other refusal surfaces as-is."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            if "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get(
            "AttachedPolicies", []
        ):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _sagemaker_role_arn(ctx):
    """Create a dedicated, self-cleaning SageMaker-assumable role and return its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="SimParity behavioral fidelity check role",
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    return resp["Role"]["Arn"]


def _definition(steps, parameters=None):
    return json.dumps(
        {
            "Version": "2020-12-01",
            "Metadata": {},
            "Parameters": parameters or [],
            "Steps": steps,
        }
    )


def _fail_step(name, message, depends_on=None):
    """A Fail step is inert: CreatePipeline only stores and validates the
    definition. Nothing is executed (no StartPipelineExecution anywhere in this
    check), so no compute is ever provisioned."""
    step = {"Name": name, "Type": "Fail", "Arguments": {"ErrorMessage": message}}
    if depends_on:
        step["DependsOn"] = depends_on
    return step


def _lambda_step(ctx, account_id, name, depends_on=None):
    """A Lambda step naming a function that does not exist.

    Inert: CreatePipeline neither invokes nor resolves the function ARN and this check never
    calls StartPipelineExecution, so no function has to exist. Lambda steps carry the DAG legs
    because AWS allows them as a DependsOn target, while Fail and Condition steps are terminal.

    `FunctionArn` is a step-level key, not a member of `Arguments`: inside Arguments it is
    refused with ValidationException "Step: [<name>]: Lambda function ARN cannot be null."
    """
    step = {
        "Name": name,
        "Type": "Lambda",
        "FunctionArn": (
            "arn:aws:lambda:%s:%s:function:sim2real-behav-inert-not-created"
            % (ctx.region, account_id)
        ),
        "Arguments": {},
        "OutputParameters": [],
    }
    if depends_on:
        step["DependsOn"] = depends_on
    return step


def _delete_pipeline(ctx, name):
    sm = ctx.client("sagemaker")
    sm.delete_pipeline(
        PipelineName=name,
        # IdempotencyToken: 32-128 chars, so the prefix must be long.
        ClientRequestToken=ctx.unique_name(
            "sim2real-behav-pipeline-delete-token-"
        ),
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePipeline refuses a DependsOn cycle, a self-dependency, an unknown or terminal (Fail)
    DependsOn target and an undeclared parameter reference, each with ValidationException and its own
    exact message, and stores none (DescribePipeline: ResourceNotFound); valid controls are stored.
    """
    sm = ctx.client("sagemaker")
    role_arn = _sagemaker_role_arn(ctx)
    # The Lambda step ARNs are minted in the same account as the pipeline role. The
    # function is never resolved (see _lambda_step), so nothing has to exist there.
    account_id = role_arn.split(":")[4]

    # --- control first: a valid, acyclic definition must be accepted. Retrying
    # here absorbs IAM propagation, which is real and slow on first use.
    control_name = ctx.unique_name("sim2real-behav-pipeline-")
    good_steps = [
        _lambda_step(ctx, account_id, "StepA"),
        _lambda_step(ctx, account_id, "StepB", depends_on=["StepA"]),
    ]
    good_definition = _definition(good_steps)
    _create_with_role_retry(
        lambda: sm.create_pipeline(
            PipelineName=control_name,
            PipelineDefinition=good_definition,
            ClientRequestToken=ctx.unique_name(
                "sim2real-behav-pipeline-create-token-"
            ),
            RoleArn=role_arn,
            Tags=[{"Key": "sim2real:check", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _delete_pipeline(ctx, control_name))
    described = sm.describe_pipeline(PipelineName=control_name)
    assert json.loads(described["PipelineDefinition"])["Steps"] == good_steps, (
        f"stored definition does not round-trip: {described['PipelineDefinition']}"
    )

    # --- every defect: refused with its OWN reason, and nothing stored.
    def _reject(what, steps, expected_message, parameters=None):
        name = ctx.unique_name("sim2real-behav-pipeline-")
        code, message = _error(
            lambda: sm.create_pipeline(
                PipelineName=name,
                PipelineDefinition=_definition(steps, parameters),
                ClientRequestToken=ctx.unique_name(
                    "sim2real-behav-pipeline-create-token-"
                ),
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real:check", "Value": CHECK}],
            )
        )
        assert code == "ValidationException", (
            f"{what}: expected ValidationException, got code={code!r} message={message!r}"
        )
        assert message == expected_message, (
            f"{what}: the refusal must name its own reason, so that a caller can tell one "
            f"definition defect from another; expected {expected_message!r}, got "
            f"{message!r}"
        )
        not_found, not_found_msg = _error(lambda: sm.describe_pipeline(PipelineName=name))
        assert not_found == "ResourceNotFound", (
            f"{what}: DescribePipeline for the rejected pipeline returned {not_found!r}; a "
            f"rejected CreatePipeline must leave nothing behind"
        )
        expected_not_found = (
            f"Pipeline 'arn:aws:sagemaker:{ctx.region}:{account_id}:pipeline/{name}' does not exist."
        )
        assert not_found_msg == expected_not_found, (
            f"{what}: expected {expected_not_found!r}, got {not_found_msg!r}"
        )
        return name

    # defect 1: a genuine two-node dependency cycle between depends-able steps.
    _reject(
        "two-node Lambda DependsOn cycle",
        [
            _lambda_step(ctx, account_id, "StepA", depends_on=["StepB"]),
            _lambda_step(ctx, account_id, "StepB", depends_on=["StepA"]),
        ],
        "Detected cycle in the DAG.",
    )

    # defect 2: the degenerate cycle -- a step depending on itself. Real AWS gives this its
    # own message rather than folding it into the DAG-cycle case, so the two are asserted
    # separately.
    _reject(
        "self-dependency",
        [_fail_step("StepA", "inert", depends_on=["StepA"])],
        "Step: StepA can not depend on itself.",
    )

    # defect 3: DependsOn naming a step that is not in the definition. This is the closest
    # NON-cycle neighbour of defect 1 -- an emulator that only counts edges rather than
    # resolving names reports a cycle here, or nothing at all.
    _reject(
        "DependsOn a step that does not exist",
        [_fail_step("StepB", "inert", depends_on=["NoSuchStep"])],
        "Step: StepB depends on unknown Step: NoSuchStep",
    )

    # defect 4: depending on a TERMINAL step. Fail (and Condition) steps end a branch and
    # may not be depended on, which is a DAG rule about node kind rather than shape.
    _reject(
        "DependsOn a terminal Fail step",
        [_fail_step("StepA", "inert"), _fail_step("StepB", "inert", depends_on=["StepA"])],
        "Step: StepB can not depends on FailStep: StepA",
    )

    # defect 5: a step argument referencing a parameter that is not declared.
    _reject(
        "reference to an undeclared parameter",
        [
            {
                "Name": "StepA",
                "Type": "Fail",
                "Arguments": {
                    "ErrorMessage": {"Get": "Parameters.NotDeclaredAnywhere"}
                },
            }
        ],
        "Unknown property reference [Parameters.NotDeclaredAnywhere].",
    )

    # --- second control: the SAME parameter reference is accepted once the parameter is
    # declared, so defect 5 is pinned to the missing declaration and not to `Get` support.
    declared_name = ctx.unique_name("sim2real-behav-pipeline-")
    declared_steps = [
        {
            "Name": "StepA",
            "Type": "Fail",
            "Arguments": {"ErrorMessage": {"Get": "Parameters.Declared"}},
        }
    ]
    declared_params = [
        {"Name": "Declared", "Type": "String", "DefaultValue": "inert"}
    ]
    sm.create_pipeline(
        PipelineName=declared_name,
        PipelineDefinition=_definition(declared_steps, declared_params),
        ClientRequestToken=ctx.unique_name("sim2real-behav-pipeline-create-token-"),
        RoleArn=role_arn,
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_pipeline(ctx, declared_name))
    declared_desc = json.loads(
        sm.describe_pipeline(PipelineName=declared_name)["PipelineDefinition"]
    )
    assert declared_desc["Steps"] == declared_steps, declared_desc
    assert declared_desc["Parameters"] == declared_params, declared_desc

    # --- control still intact and listable after every rejection.
    summaries = sm.list_pipelines(
        PipelineNamePrefix=control_name, MaxResults=100
    )["PipelineSummaries"]
    assert [s["PipelineName"] for s in summaries] == [control_name], (
        f"ListPipelines(prefix={control_name}) returned "
        f"{[s['PipelineName'] for s in summaries]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
