"""apigateway-invoke-surfaces-backend-status-as-apigateway-dot-code-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigateway-invoke-surfaces-backend-status-as-apigateway-dot-code-error"
GROUP = "task_integrations"
SERVICES = ["apigateway", "stepfunctions", "iam", "sts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An apigateway:invoke task reports a non-2XX MOCK backend response as error
    ApiGateway.<HTTP Status Code> with a string cause, while a 2XX response still succeeds.
    """
    ag = ctx.client("apigateway")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    _add_mock_get_method(ctx, ag, api_id, root_id, 200, '{"marker":"ok"}')
    err500_id = _create_resource(ctx, ag, api_id, root_id, "err500")
    _add_mock_get_method(ctx, ag, api_id, err500_id, 500, '{"marker":"err500"}')
    err404_id = _create_resource(ctx, ag, api_id, root_id, "err404")
    _add_mock_get_method(ctx, ag, api_id, err404_id, 404, '{"marker":"err404"}')
    # The resource policy must be set BEFORE the first deployment: a policy attached to an
    # already-deployed stage does not take effect on it, even after a long wait.
    _set_resource_policy(ctx, ag, api_id, account_id, sm_arn)
    stage = _deploy(ctx, ag, api_id)

    desc, output = _run_to_terminal(ctx, sm_arn, api_id, stage)
    assert desc["status"] == "SUCCEEDED", (
        f'execution ended {desc["status"]!r}: {desc.get("error")!r} {desc.get("cause")!r}'
    )
    ok, err500, err404 = output

    assert ok["StatusCode"] == 200 and ok["ResponseBody"] == {"marker": "ok"}, (
        f"the 2XX branch's output was {ok!r}"
    )

    assert err500["Error"] == "ApiGateway.500", f"the 500 branch's error was {err500['Error']!r}"
    assert isinstance(err500["Cause"], str) and err500["Cause"] == '{"marker":"err500"}', (
        f"the 500 branch's cause was {err500['Cause']!r}"
    )

    assert err404["Error"] == "ApiGateway.404", f"the 404 branch's error was {err404['Error']!r}"
    assert isinstance(err404["Cause"], str) and err404["Cause"] == '{"marker":"err404"}', (
        f"the 404 branch's cause was {err404['Cause']!r}"
    )


# ===== helpers =====

def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _create_resource(ctx, ag, api_id, parent_id, path_part):
    return ag.create_resource(
        restApiId=api_id, parentId=parent_id, pathPart=path_part,
    )["id"]


def _create_api(ctx, ag):
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK[:200]},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: ag.delete_rest_api(restApiId=api_id), "NotFoundException"))
    return api_id


def _add_mock_get_method(ctx, ag, api_id, resource_id, status_code, response_body):
    status = str(status_code)
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                   authorizationType="AWS_IAM")
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": f'{{"statusCode": {status}}}'},
    )
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                            statusCode=status)
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode=status,
        selectionPattern="", responseTemplates={"application/json": response_body},
    )


def _deploy(ctx, ag, api_id):
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = ctx.unique_name("s")[:60].lower().replace("-", "")
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=deployment_id,
                     tags={"sim2real": CHECK[:200]})
    ctx.on_cleanup(_teardown(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage), "NotFoundException"))
    return stage


def _set_resource_policy(ctx, ag, api_id, account_id, sm_arn):
    """Allow execute-api:Invoke on this API only to Step Functions acting for this check's
    state machine (the RESOURCE_POLICY caller)."""
    resource = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "execute-api:Invoke",
            "Resource": resource,
            "Condition": {"StringEquals": {"aws:SourceArn": sm_arn}},
        }],
    }
    ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/policy", "value": json.dumps(policy)}],
    )
    _poll_until(
        lambda: ag.get_rest_api(restApiId=api_id).get("policy"),
        lambda p: p is not None and "states.amazonaws.com" in p,
        timeout_s=60.0,
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s. Last: {last!r}")


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke",
                           "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _branch(name, path):
    params = {
        "ApiEndpoint.$": "$.apiEndpoint",
        "Method": "GET",
        "Stage.$": "$.stage",
        "AuthType": "RESOURCE_POLICY",
    }
    if path:
        params["Path"] = path
    invoke_name = f"Invoke{name}"
    done_name = f"Done{name}"
    return {
        "StartAt": invoke_name,
        "States": {
            invoke_name: {
                "Type": "Task",
                "Resource": "arn:aws:states:::apigateway:invoke",
                "Parameters": params,
                "Catch": [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.caught",
                           "Next": done_name}],
                "End": True,
            },
            done_name: {"Type": "Pass", "OutputPath": "$.caught", "End": True},
        },
    }


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: three apigateway:invoke tasks with AuthType RESOURCE_POLICY",
        "StartAt": "Probe",
        "States": {
            "Probe": {
                "Type": "Parallel",
                "Branches": [
                    _branch("Ok", None),
                    _branch("Err500", "err500"),
                    _branch("Err404", "err404"),
                ],
                "End": True,
            },
        },
    }
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK[:200]}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
            return arn
        except ClientError as exc:
            got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
            if got != _ROLE_NOT_ASSUMABLE:
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


_ROLE_NOT_ASSUMABLE = (
    "AccessDeniedException",
    "Neither the global service principal states.amazonaws.com, nor the regional one is "
    "authorized to assume the provided role.",
)
_EXPECTED_ERRORS = ("ApiGateway.500", "ApiGateway.404")


def _start(ctx, sm_arn, api_id, stage):
    sfn = ctx.client("stepfunctions")
    payload = {
        "apiEndpoint": f"{api_id}.execute-api.{ctx.region}.amazonaws.com",
        "stage": stage,
    }
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="sim2real-cleanup", cause="cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s=90.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal(ctx, sm_arn, api_id, stage, *, propagation_s=120.0):
    """Run one execution to its end, starting a fresh one until the 2XX branch succeeds and the
    error branches report the asserted ApiGateway.<code> errors.

    Every branch catches its own task failure, so a propagation race of the role's trust or
    the API's resource policy surfaces inside the execution's (successful) output.
    """
    retry_until = time.monotonic() + propagation_s
    while True:
        exec_arn = _start(ctx, sm_arn, api_id, stage)
        desc = _wait_terminal(ctx, exec_arn)
        if desc["status"] != "SUCCEEDED":
            return desc, None
        output = json.loads(desc["output"])
        ok, err500, err404 = output
        if ok.get("StatusCode") == 200 and (
            err500.get("Error"), err404.get("Error")) == _EXPECTED_ERRORS:
            return desc, output
        if time.monotonic() >= retry_until:
            return desc, output
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
