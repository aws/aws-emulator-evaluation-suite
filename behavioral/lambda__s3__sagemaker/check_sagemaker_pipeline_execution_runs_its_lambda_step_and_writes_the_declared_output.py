"""sagemaker-pipeline-execution-runs-its-lambda-step-and-writes-the-declared-output."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-pipeline-execution-runs-its-lambda-step-and-writes-the-declared-output"
GROUP = 'execution'
SERVICES = ['lambda', 's3', 'sagemaker']

# The step writes the event it received to S3 and returns two values so the executor's
# OutputParameters mapping is observable.
_LAMBDA_SRC = '''
import json
import boto3

def handler(event, context):
    s3 = boto3.client("s3")
    key = event["key"]
    s3.put_object(Bucket=event["bucket"], Key=key,
                  Body=json.dumps(event, sort_keys=True).encode("utf-8"))
    return {"written_key": key, "marker_seen": event.get("marker")}
'''


def _quiet(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _create_bucket(ctx: Any, s3: Any, bucket: str, scenario: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]}
    )


def _delete_bucket(s3: Any, bucket: str) -> None:
    """Empty then delete the bucket, verifying the delete took effect."""
    try:
        while True:
            resp = s3.list_objects_v2(Bucket=bucket)
            contents = resp.get("Contents", [])
            if not contents:
                break
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx: Any, iam: Any, role_name: str, service: str, statements: list) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": service},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "pipeline-execution"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scoped",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    """IAM roles are eventually consistent; poll the actual call until SageMaker can use it.

    A not-yet-propagated RoleArn surfaces as a ValidationException naming the role.
    """
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


def _delete_role(iam: Any, role_name: str) -> None:
    for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    iam.delete_role(RoleName=role_name)


def _create_function(ctx: Any, lam: Any, name: str, role_arn: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", _LAMBDA_SRC)
    deadline = time.monotonic() + 120
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                Tags={"sim2real": "pipeline-execution"},
            )["FunctionArn"]
            break
        except ClientError as exc:
            # The bounded retry on the role not yet being assumable by Lambda.
            if exc.response["Error"]["Code"] == "InvalidParameterValueException" \
                    and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return arn


def _wait_execution_terminal(sm: Any, arn: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_pipeline_execution(PipelineExecutionArn=arn)
        if desc["PipelineExecutionStatus"] in ("Succeeded", "Failed", "Stopped"):
            return desc
        time.sleep(3)
    raise AssertionError(
        f"pipeline execution {arn} never reached a terminal state within {timeout_s}s: {desc}"
    )


def _all_steps(sm: Any, arn: str) -> list:
    steps, token = [], None
    while True:
        kw = {"PipelineExecutionArn": arn, "MaxResults": 100}
        if token:
            kw["NextToken"] = token
        resp = sm.list_pipeline_execution_steps(**kw)
        steps.extend(resp["PipelineExecutionSteps"])
        token = resp.get("NextToken")
        if not token:
            return steps


def _run_execution_until_permission_ready(
    ctx: Any, sm: Any, definition: dict, pipeline_role: str, marker: str,
    *, timeout_s: float, retry_budget_s: float = 60.0,
) -> tuple[str, str, dict]:
    """Create a pipeline and run it, retrying on a fresh pipeline while pipeline_role propagates.

    The execution can still fail on role propagation after CreatePipeline accepted the role.
    """
    deadline = time.monotonic() + retry_budget_s
    while True:
        pipeline = ctx.unique_name("sim2real-sm-pl-pipe-")
        _retry_role_propagation(lambda: sm.create_pipeline(
            PipelineName=pipeline,
            PipelineDefinition=json.dumps(definition),
            RoleArn=pipeline_role,
            Tags=[{"Key": "sim2real", "Value": "pipeline-execution"}],
        ))
        ctx.on_cleanup(lambda p=pipeline: _quiet(lambda: sm.delete_pipeline(PipelineName=p)))

        execution_arn = sm.start_pipeline_execution(
            PipelineName=pipeline,
            PipelineParameters=[{"Name": "Marker", "Value": marker}],
        )["PipelineExecutionArn"]
        exec_desc = _wait_execution_terminal(sm, execution_arn, timeout_s=timeout_s)
        if exec_desc["PipelineExecutionStatus"] == "Succeeded":
            break

        steps = _all_steps(sm, execution_arn)
        reason = (steps[0].get("FailureReason") or "") if steps else ""
        # A real explicit Deny is never retried away.
        not_yet_propagated = (
            ("is not authorized to perform: lambda:InvokeFunction" in reason
             and "explicit deny" not in reason)
            or "does not exist or does not trust" in reason
        )
        # A fresh pipeline per retry keeps exactly one execution per pipeline.
        if not_yet_propagated and time.monotonic() < deadline:
            time.sleep(5)
            continue
        break

    assert exec_desc["PipelineExecutionStatus"] == "Succeeded", (
        f"the pipeline execution did not succeed: status="
        f"{exec_desc['PipelineExecutionStatus']!r} reason={exec_desc.get('FailureReason')!r} "
        f"step_reason={reason!r}"
    )
    return pipeline, execution_arn, exec_desc


def _all_executions(sm: Any, pipeline: str) -> list:
    out, token = [], None
    while True:
        kw = {"PipelineName": pipeline, "MaxResults": 100}
        if token:
            kw["NextToken"] = token
        resp = sm.list_pipeline_executions(**kw)
        out.extend(resp["PipelineExecutionSummaries"])
        token = resp.get("NextToken")
        if not token:
            return out


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Executing a pipeline whose single Lambda step writes a marker object lands that object in S3
    with the StartPipelineExecution parameter value, and the step's return value comes back as its
    OutputParameters, in exactly one execution.

    Reference: https://docs.aws.amazon.com/sagemaker/latest/dg/build-and-manage-steps.html
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sm = ctx.client("sagemaker")
    timeout_s = 420

    bucket = ctx.unique_name("sim2real-sm-pl-")
    _create_bucket(ctx, s3, bucket, "pipeline-execution")

    lambda_role = _create_role(
        ctx, iam, ctx.unique_name("sim2real-sm-pl-lrole-"), "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": ["s3:PutObject"],
          "Resource": f"arn:aws:s3:::{bucket}/*"}],
    )
    function_name = ctx.unique_name("sim2real-sm-pl-fn-")
    function_arn = _create_function(ctx, lam, function_name, lambda_role)

    pipeline_role = _create_role(
        ctx, iam, ctx.unique_name("sim2real-sm-pl-prole-"), "sagemaker.amazonaws.com",
        [{"Effect": "Allow", "Action": ["lambda:InvokeFunction"], "Resource": function_arn}],
    )

    marker = ctx.unique_name("marker-")
    key = "out/step-output.json"
    definition = {
        "Version": "2020-12-01",
        "Parameters": [{"Name": "Marker", "Type": "String", "DefaultValue": "unset"}],
        "Steps": [{
            "Name": "WriteMarker",
            "Type": "Lambda",
            "FunctionArn": function_arn,
            "Arguments": {
                "bucket": bucket,
                "key": key,
                # Resolved by the executor at run time -- never by this check.
                "marker": {"Get": "Parameters.Marker"},
            },
            "OutputParameters": [{"OutputName": "written_key", "OutputType": "String"}],
        }],
    }
    pipeline, execution_arn, _exec_desc = _run_execution_until_permission_ready(
        ctx, sm, definition, pipeline_role, marker, timeout_s=timeout_s,
    )

    described = sm.describe_pipeline(PipelineName=pipeline)
    stored = json.loads(described["PipelineDefinition"])
    assert [p["Name"] for p in stored["Parameters"]] == ["Marker"], (
        f"DescribePipeline did not round-trip the declared parameter: {stored.get('Parameters')!r}"
    )

    # An S3 object no SageMaker API wrote, containing a value this check minted.
    written = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
    assert written["marker"] == marker, (
        f"the StartPipelineExecution parameter never reached the step: the function was handed "
        f"marker={written.get('marker')!r}, expected {marker!r}"
    )
    assert written["bucket"] == bucket and written["key"] == key, (
        f"the step received a payload that does not match its declared Arguments: {written!r}"
    )

    steps = _all_steps(sm, execution_arn)
    assert len(steps) == 1, (
        f"exactly one step was defined, so exactly one must be reported: "
        f"{[s.get('StepName') for s in steps]!r}"
    )
    step = steps[0]
    assert step["StepName"] == "WriteMarker", step
    assert step["StepStatus"] == "Succeeded", (
        f"the step that demonstrably wrote the object is not reported Succeeded: {step!r}"
    )
    assert step["Metadata"]["Lambda"]["Arn"] == function_arn, (
        f"the step metadata must name the function that actually ran: "
        f"{step['Metadata']!r}, expected {function_arn!r}"
    )
    returned = {
        p["Name"]: p["Value"] for p in step["Metadata"]["Lambda"].get("OutputParameters", [])
    }
    assert returned.get("written_key") == key, (
        f"the executor must surface the value the function RETURNED as the step's output: "
        f"{returned!r}, expected written_key={key!r}"
    )
    assert returned.get("marker_seen") == marker, (
        f"the step output must carry the marker the function saw, which closes the loop from the "
        f"execution parameter back through the function: {returned!r}"
    )
    assert step["StartTime"] <= step["EndTime"], (
        f"the step's timings are not ordered: {step['StartTime']!r} .. {step['EndTime']!r}"
    )
    assert step["AttemptCount"] == 1, (
        f"a step that succeeded first time must report one attempt: {step['AttemptCount']!r}"
    )

    # Effect bounded: starting one execution started exactly one.
    executions = _all_executions(sm, pipeline)
    assert [e["PipelineExecutionArn"] for e in executions] == [execution_arn], (
        f"exactly one execution must exist for this pipeline: "
        f"{[e['PipelineExecutionArn'] for e in executions]!r}"
    )
    assert executions[0]["PipelineExecutionStatus"] == "Succeeded", executions[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
