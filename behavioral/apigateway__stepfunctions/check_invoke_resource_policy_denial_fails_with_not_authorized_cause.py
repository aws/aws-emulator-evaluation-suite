"""invoke-resource-policy-denial-fails-with-not-authorized-cause."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-resource-policy-denial-fails-with-not-authorized-cause"
GROUP = "task_integrations"
SERVICES = ["apigateway", "stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AuthType RESOURCE_POLICY apigateway:invoke task fails with ApiGateway.AccessDeniedException
    when the API's resource policy denies every caller, while the same task invokes a sibling
    AWS_IAM API whose resource policy allows Step Functions acting for this state machine.
    """
    ag = ctx.client("apigateway")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # The state machine comes first: the allowing policy names it as the aws:SourceArn.
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    denied_api = _create_api(ctx, ag)
    _add_mock_get_method(ctx, ag, denied_api, "NONE")
    allowed_api = _create_api(ctx, ag)
    # A principal-scoped Allow matches only a SigV4-authenticated caller, so the allowed
    # method uses AWS_IAM; with NONE the caller is anonymous and the Allow never applies.
    _add_mock_get_method(ctx, ag, allowed_api, "AWS_IAM")
    # The resource policy must be set BEFORE the first deployment: a policy attached to an
    # already-deployed stage does not take effect on it, even after a long wait.
    _set_resource_policy(ctx, ag, denied_api, account_id, sm_arn, effect="Deny")
    _set_resource_policy(ctx, ag, allowed_api, account_id, sm_arn, effect="Allow")
    denied_stage = _deploy(ctx, ag, denied_api)
    allowed_stage = _deploy(ctx, ag, allowed_api)

    _, desc = _run_to_terminal(ctx, sm_arn, denied_api, denied_stage)
    assert desc["status"] == "FAILED", (
        f"execution ended {desc['status']!r}, expected FAILED: {desc.get('cause')!r}"
    )
    assert desc["error"] == "ApiGateway.AccessDeniedException", f"the task's error was {desc['error']!r}"
    assert desc["cause"] == "Not authorized to perform: execute-api:Invoke on the resource", (
        f"the task's cause was {desc['cause']!r}"
    )

    # Positive control: the same task against a sibling API whose resource policy allows
    # Step Functions for this state machine succeeds and reaches the MOCK integration.
    # Until the fresh stage's policy propagates, API Gateway may still refuse the call.
    _, ok_desc = _run_to_terminal(ctx, sm_arn, allowed_api, allowed_stage,
                                  transient_errors=("ApiGateway.AccessDeniedException",))
    assert ok_desc["status"] == "SUCCEEDED", (
        f"the allowed-policy sibling ended {ok_desc['status']!r}: "
        f"{ok_desc.get('error')!r} {ok_desc.get('cause')!r}"
    )
    out = json.loads(ok_desc["output"])
    assert out["StatusCode"] == 200 and out["ResponseBody"] == {"marker": "ok"}, (
        f"the allowed-policy sibling's output was {out!r}"
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


def _create_api(ctx, ag):
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK[:200]},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: ag.delete_rest_api(restApiId=api_id), "NotFoundException"))
    return api_id


def _add_mock_get_method(ctx, ag, api_id, authorization):
    resource_id = _root_id(ag, api_id)
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                   authorizationType=authorization)
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                            statusCode="200")
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": '{"marker":"ok"}'},
    )


def _deploy(ctx, ag, api_id):
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = ctx.unique_name("s")[:60].lower().replace("-", "")
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=deployment_id,
                     tags={"sim2real": CHECK[:200]})
    ctx.on_cleanup(_teardown(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage), "NotFoundException"))
    return stage


def _set_resource_policy(ctx, ag, api_id, account_id, sm_arn, *, effect):
    """A resource policy that denies every caller execute-api:Invoke, or allows it only to
    Step Functions acting for this check's state machine (the RESOURCE_POLICY caller)."""
    resource = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*"
    if effect == "Allow":
        statement = {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "execute-api:Invoke",
            "Resource": resource,
            "Condition": {"StringEquals": {"aws:SourceArn": sm_arn}},
        }
    else:
        statement = {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": resource,
        }
    policy = {"Version": "2012-10-17", "Statement": [statement]}
    ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/policy", "value": json.dumps(policy)}],
    )
    # Confirms the control-plane write landed before the (pre-first-deployment) deploy call.
    _poll_until(
        lambda: ag.get_rest_api(restApiId=api_id).get("policy"),
        lambda p: p is not None and effect in p,
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


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: one apigateway:invoke task with AuthType RESOURCE_POLICY",
        "StartAt": "Invoke",
        "States": {
            "Invoke": {
                "Type": "Task",
                "Resource": "arn:aws:states:::apigateway:invoke",
                "Parameters": {
                    "ApiEndpoint.$": "$.apiEndpoint",
                    "Method": "GET",
                    "Stage.$": "$.stage",
                    "AuthType": "RESOURCE_POLICY",
                },
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
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "security token included in the request is invalid",
)


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


def _wait_terminal(ctx, exec_arn, *, timeout_s=60.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal(ctx, sm_arn, api_id, stage, *, propagation_s=90.0, transient_errors=()):
    """Run one execution to its end, starting a fresh one while the role's trust, or for a
    caller that names them, the API's allowing policy (transient_errors), still propagate."""
    retry_until = time.monotonic() + propagation_s
    while True:
        exec_arn = _start(ctx, sm_arn, api_id, stage)
        desc = _wait_terminal(ctx, exec_arn)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        transient = (any(m in blob for m in _PROPAGATION_MARKERS)
                     or desc.get("error") in transient_errors)
        if desc["status"] != "FAILED" or not transient:
            return exec_arn, desc
        if time.monotonic() >= retry_until:
            return exec_arn, desc
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
