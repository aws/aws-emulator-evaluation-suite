"""deploy-cdk-synth-express-workflow-lambda-sqs-stack."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-synth-express-workflow-lambda-sqs-stack"
GROUP = "deploy-stack"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CDK-synthesized Express state machine's role can invoke Lambda and send to SQS: a synchronous
    execution returns the Lambda output and delivers a message carrying it to the queue."""
    require_tools("cdk")

    app_dir = Path(tempfile.mkdtemp(prefix="sim2real-xsvc-cdkapp-"))
    ctx.on_cleanup(lambda: shutil.rmtree(app_dir, ignore_errors=True))
    (app_dir / "cdk.json").write_text(json.dumps({"app": "python3 app.py"}))
    (app_dir / "app.py").write_text(_CDK_APP_SOURCE)

    deployed = _deploy_cdk(ctx, app_dir)
    sm_arn = deployed["outputs"]["StateMachineArn"]
    queue_url = deployed["outputs"]["QueueUrl"]

    sfn = ctx.client("stepfunctions")
    sqs = ctx.client("sqs")

    marker = ctx.unique_name("cdk-express")
    result = sfn.start_sync_execution(
        stateMachineArn=sm_arn, input=json.dumps({"value": marker})
    )
    assert result["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {result['status']}: {result.get('error')} {result.get('cause')}"
    )

    # The Lambda invocation actually ran: its echoed output is visible in the sync result.
    output = json.loads(result["output"])
    assert output["echo"]["value"] == marker, (
        f"expected Lambda to echo marker {marker!r}, sync execution output was {output!r}"
    )

    # The SQS send task actually delivered a message carrying that same Lambda output.
    delivered = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=30,
        interval_s=2.0,
        description="message delivered to queue",
    )
    body = json.loads(delivered[0]["Body"])
    assert body["echo"]["value"] == marker, (
        f"expected queue message body to carry marker {marker!r}, got {body!r}"
    )


_CDK_APP_SOURCE = '''
from aws_cdk import App, Stack, Duration, CfnOutput
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks


class ExpressWorkflowStack(Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        queue = sqs.Queue(self, "Queue")

        fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(
                "def handler(event, context):\\n    return {'echo': event}\\n"
            ),
            timeout=Duration.seconds(10),
        )

        invoke = tasks.LambdaInvoke(
            self, "InvokeFn", lambda_function=fn, output_path="$.Payload"
        )
        send = tasks.SqsSendMessage(
            self,
            "SendToQueue",
            queue=queue,
            message_body=sfn.TaskInput.from_json_path_at("$"),
            result_path=sfn.JsonPath.DISCARD,
        )
        definition = invoke.next(send)

        machine = sfn.StateMachine(
            self,
            "Machine",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            state_machine_type=sfn.StateMachineType.EXPRESS,
        )

        CfnOutput(self, "StateMachineArn", value=machine.state_machine_arn)
        CfnOutput(self, "QueueUrl", value=queue.queue_url)


app = App()
ExpressWorkflowStack(app, "Sim2RealExpressStack")
app.synth()
'''


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


_CDK_BOOTSTRAP_PARAM = "BootstrapVersion"

_CDK_BOOTSTRAP_RULE = "CheckBootstrapVersion"


def _strip_cdk_bootstrap(template_json: str) -> str:
    """Remove the BootstrapVersion parameter and CheckBootstrapVersion rule CDK adds to every template.
    CloudFormation resolves that SSM default at CreateStack and fails in an un-bootstrapped account;
    only that rule uses the parameter, so dropping both is equivalent for an asset-free stack."""
    doc = json.loads(template_json)
    params = doc.get("Parameters") or {}
    rules = doc.get("Rules") or {}
    params.pop(_CDK_BOOTSTRAP_PARAM, None)
    rules.pop(_CDK_BOOTSTRAP_RULE, None)
    for key, value in (("Parameters", params), ("Rules", rules)):
        if value:
            doc[key] = value
        else:
            doc.pop(key, None)

    rest = json.dumps(doc)
    for marker in ("/cdk-bootstrap/", "cdk-hnb659fds-assets"):
        if marker in rest:
            raise AssertionError(
                f"CDK app needs a bootstrapped environment ({marker} referenced) — it has file or "
                "image assets. Make the app asset-free (inline Lambda code as a string) so the "
                "synthesized template deploys through plain CloudFormation."
            )
    return rest


def _deploy_cdk(
    ctx, app_dir, *, stack=None, context=None, timeout_s=300.0
) -> dict[str, Any]:
    """``cdk synth`` an app in an ISOLATED temp COPY, then deploy the SYNTHESIZED CloudFormation
    template through ``_deploy_cfn``. Returns ``_deploy_cfn``'s {stack_name,stack_id,outputs}."""
    require_tools("cdk")
    ctx.verify_account_safety()

    src = Path(app_dir)
    work = Path(tempfile.mkdtemp(prefix="sim2real-xsvc-cdk-"))
    shutil.copytree(
        src,
        work,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("cdk.out", ".venv", "__pycache__", "node_modules"),
    )
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))

    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]

    asm = work / "cdk.out"
    cmd = [
        "cdk", "synth",
        "--output", str(asm),
        "--ci",
        "--no-version-reporting",
        "--no-asset-metadata",
        "--no-path-metadata",
    ]
    if stack:
        cmd.append(stack)
    for k, v in (context or {}).items():
        cmd.extend(["--context", f"{k}={v}"])
    synth = subprocess.run(
        cmd, cwd=work, env=env, capture_output=True, text=True, timeout=180,
    )
    if synth.returncode != 0:
        raise AssertionError(f"cdk synth failed: {synth.stderr[-500:]}")

    templates = sorted(asm.glob("*.template.json"))
    if stack:
        templates = [t for t in templates if t.name == f"{stack}.template.json"] or templates
    if not templates:
        raise AssertionError(f"cdk synth produced no template in {asm}")
    if len(templates) > 1:
        names = ", ".join(t.name[: -len(".template.json")] for t in templates)
        raise AssertionError(f"app synthesized {len(templates)} stacks ({names}) — pass stack=...")

    return _deploy_cfn(
        ctx, _strip_cdk_bootstrap(templates[0].read_text()), timeout_s=timeout_s
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
