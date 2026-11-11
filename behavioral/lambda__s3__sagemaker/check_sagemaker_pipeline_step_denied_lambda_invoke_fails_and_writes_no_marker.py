"""sagemaker-pipeline-step-denied-lambda-invoke-fails-and-writes-no-marker."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-pipeline-step-denied-lambda-invoke-fails-and-writes-no-marker"
GROUP = 'overly-permissive'
SERVICES = ['lambda', 's3', 'sagemaker']

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
        Tags=[{"Key": "sim2real", "Value": "pipeline-denied-invoke"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scoped",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return arn


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
                Tags={"sim2real": "pipeline-denied-invoke"},
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException" \
                    and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return arn


def _definition(function_arn: str, bucket: str, key: str) -> str:
    return json.dumps({
        "Version": "2020-12-01",
        "Parameters": [{"Name": "Marker", "Type": "String", "DefaultValue": "unset"}],
        "Steps": [{
            "Name": "WriteMarker",
            "Type": "Lambda",
            "FunctionArn": function_arn,
            "Arguments": {
                "bucket": bucket,
                "key": key,
                "marker": {"Get": "Parameters.Marker"},
            },
            "OutputParameters": [{"OutputName": "written_key", "OutputType": "String"}],
        }],
    })


def _run_pipeline(ctx: Any, sm: Any, name: str, definition: str, role_arn: str, marker: str,
                  *, timeout_s: float) -> tuple[dict, list]:
    sm.create_pipeline(
        PipelineName=name,
        PipelineDefinition=definition,
        RoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": "pipeline-denied-invoke"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_pipeline(PipelineName=name)))
    arn = sm.start_pipeline_execution(
        PipelineName=name,
        PipelineParameters=[{"Name": "Marker", "Value": marker}],
    )["PipelineExecutionArn"]
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_pipeline_execution(PipelineExecutionArn=arn)
        if desc["PipelineExecutionStatus"] in ("Succeeded", "Failed", "Stopped"):
            break
        time.sleep(3)
    else:
        raise AssertionError(
            f"pipeline execution {arn} never reached a terminal state within {timeout_s}s: {desc}"
        )
    steps, token = [], None
    while True:
        kw = {"PipelineExecutionArn": arn, "MaxResults": 100}
        if token:
            kw["NextToken"] = token
        resp = sm.list_pipeline_execution_steps(**kw)
        steps.extend(resp["PipelineExecutionSteps"])
        token = resp.get("NextToken")
        if not token:
            break
    return desc, steps


def _run_pipeline_until_settled(ctx: Any, sm: Any, name_prefix: str, definition: str, role_arn: str,
                                 marker: str, *, timeout_s: float, want_status: str,
                                 settle_deadline_s: float = 90.0) -> tuple[dict, list]:
    """Run a FRESH execution, retrying only while the mismatch reads as IAM propagation lag.

    IAM has no propagation API; an unexpected Succeeded on the deny leg means the Deny is not live.
    """
    deadline = time.monotonic() + settle_deadline_s
    attempt = 0
    while True:
        attempt += 1
        desc, steps = _run_pipeline(
            ctx, sm, ctx.unique_name(f"{name_prefix}-{attempt}-"), definition, role_arn, marker,
            timeout_s=timeout_s,
        )
        reason = (steps[0].get("FailureReason") or "") if steps else ""
        # SageMaker's own role-trust pre-check message is unambiguous and never overlaps the
        # real Deny wording, so it is safe to catch on either leg. The generic "not
        # authorized"/AssumeRole wording, however, is also exactly what a SUCCESSFUL Deny
        # produces (the deny leg's correct terminal state) -- so it must only be read as
        # propagation on the leg that is not expecting a Deny.
        propagation_signal = (
            "does not exist or does not trust" in reason
            or (want_status == "Succeeded" and desc["PipelineExecutionStatus"] != want_status
                and ("AssumeRole" in reason or "is not authorized" in reason))
            or (want_status == "Failed" and desc["PipelineExecutionStatus"] == "Succeeded")
        )
        if not propagation_signal or time.monotonic() >= deadline:
            return desc, steps
        time.sleep(5)


def _head_code(s3: Any, bucket: str, key: str) -> str:
    """The error code HeadObject raises; raises AssertionError if the object EXISTS."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"HeadObject on s3://{bucket}/{key} succeeded: the object exists")


def _object_exists(s3: Any, bucket: str, key: str) -> bool:
    """True if HeadObject finds the object, False on 404; any other error propagates."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "404":
            return False
        raise
    return True


@tags("axis:rejection", "cap:c3", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A step whose role has an explicit Deny on lambda:InvokeFunction fails with that refusal,
    empty step Metadata and no marker, while an identical granted pipeline Succeeds; restoring the
    same role to Allow makes the denied pipeline succeed again.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sm = ctx.client("sagemaker")
    timeout_s = 420

    bucket = ctx.unique_name("sim2real-sm-pl-")
    _create_bucket(ctx, s3, bucket, "pipeline-denied-invoke")

    lambda_role = _create_role(
        ctx, iam, ctx.unique_name("sim2real-sm-pl-lrole-"), "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": ["s3:PutObject"],
          "Resource": f"arn:aws:s3:::{bucket}/*"}],
    )
    function_name = ctx.unique_name("sim2real-sm-pl-fn-")
    function_arn = _create_function(ctx, lam, function_name, lambda_role)

    marker = ctx.unique_name("marker-")
    allowed_key = "out/allowed.json"
    denied_key = "out/denied.json"

    # --- POSITIVE CONTROL FIRST: it is the propagation barrier, since a not-yet-propagated Allow
    # fails with "not authorized" wording that resembles the denial under test. ---
    allow_role = _create_role(
        ctx, iam, ctx.unique_name("sim2real-sm-pl-allow-"), "sagemaker.amazonaws.com",
        [{"Effect": "Allow", "Action": ["lambda:InvokeFunction"], "Resource": function_arn}],
    )
    good_desc, good_steps = _run_pipeline_until_settled(
        ctx, sm, "sim2real-sm-pl-good", _definition(function_arn, bucket, allowed_key),
        allow_role, marker, timeout_s=timeout_s, want_status="Succeeded",
    )
    assert good_desc["PipelineExecutionStatus"] == "Succeeded", (
        f"positive control: the granted pipeline must run before anything is broken, else a "
        f"propagation delay would masquerade as the denial under test: "
        f"status={good_desc['PipelineExecutionStatus']!r} "
        f"reason={good_desc.get('FailureReason')!r} steps={good_steps!r}"
    )
    assert _object_exists(s3, bucket, allowed_key), (
        f"positive control: the granted pipeline reported Succeeded but wrote no object at "
        f"{allowed_key!r}"
    )
    control_written = json.loads(s3.get_object(Bucket=bucket, Key=allowed_key)["Body"].read())
    assert control_written["marker"] == marker, (
        f"positive control: the granted step ran with the wrong payload: {control_written!r}"
    )

    # --- Break exactly one thing: the pipeline role may not invoke the function. ---
    deny_role_name = ctx.unique_name("sim2real-sm-pl-deny-")
    deny_role = _create_role(
        ctx, iam, deny_role_name, "sagemaker.amazonaws.com",
        [{"Effect": "Deny", "Action": ["lambda:InvokeFunction"], "Resource": function_arn}],
    )
    bad_desc, bad_steps = _run_pipeline_until_settled(
        ctx, sm, "sim2real-sm-pl-bad", _definition(function_arn, bucket, denied_key),
        deny_role, marker, timeout_s=timeout_s, want_status="Failed",
    )

    assert bad_desc["PipelineExecutionStatus"] == "Failed", (
        f"an execution whose role cannot invoke its step's function must fail, not succeed: "
        f"status={bad_desc['PipelineExecutionStatus']!r} steps={bad_steps!r}"
    )
    assert len(bad_steps) == 1, (
        f"exactly one step was defined: {[s.get('StepName') for s in bad_steps]!r}"
    )
    bad_step = bad_steps[0]
    assert bad_step["StepStatus"] == "Failed", (
        f"the step that could not be invoked must be reported Failed: {bad_step!r}"
    )
    # The reason names the refused action, the function, and the explicit Deny this check
    # installed -- a not-yet-propagated Allow produces a superficially similar 'not authorized'
    # message and would make this check pass for the wrong reason.
    reason = bad_step.get("FailureReason") or ""
    account = function_arn.split(":")[4]
    # SageMaker assumes the role with session name sagemaker-pipeline-<execution id>-<step name>.
    execution_id = bad_desc["PipelineExecutionArn"].rsplit("/", 1)[-1]
    session = f"sagemaker-pipeline-{execution_id}-{bad_step['StepName']}"
    expected_reason = (
        f"ClientError: User: arn:aws:sts::{account}:assumed-role/{deny_role_name}/{session} is not authorized "
        f"to perform: lambda:InvokeFunction on resource: {function_arn} with an explicit deny in "
        f"an identity-based policy"
    )
    assert reason == expected_reason, (
        f"the step's FailureReason must be AWS's exact explicit-deny refusal: {reason!r}"
    )

    # Effect absent, three ways.
    assert bad_step["Metadata"] == {}, (
        f"a step that was never invoked must carry no Lambda metadata -- an Arn or an "
        f"OutputParameters list here would mean the function ran anyway: {bad_step['Metadata']!r}"
    )
    denied_head = _head_code(s3, bucket, denied_key)
    assert denied_head == "404", (
        f"the denied step must have written nothing at {denied_key!r}; HeadObject returned "
        f"{denied_head!r}"
    )
    all_keys = sorted(
        o["Key"] for o in s3.list_objects_v2(Bucket=bucket, Prefix="out/").get("Contents", [])
    )
    assert all_keys == [allowed_key], (
        f"only the granted pipeline may have written under out/: {all_keys!r}"
    )
    # The granted pipeline's object is untouched by the failed run.
    still = json.loads(s3.get_object(Bucket=bucket, Key=allowed_key)["Body"].read())
    assert still == control_written, (
        f"the failed execution changed the control object: {still!r} != {control_written!r}"
    )

    # --- Restore: the identical role, no longer denied, must work. A policy denial is the
    # broken-then-restored class of negative, not an always-invalid input -- so the check must
    # prove the block is reversible, not merely that this particular role variant never works. ---
    iam.put_role_policy(
        RoleName=deny_role_name,
        PolicyName="scoped",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["lambda:InvokeFunction"], "Resource": function_arn}
            ],
        }),
    )
    restored_key = "out/restored.json"
    restored_desc, restored_steps = _run_pipeline_until_settled(
        ctx, sm, "sim2real-sm-pl-restored", _definition(function_arn, bucket, restored_key),
        deny_role, marker, timeout_s=timeout_s, want_status="Succeeded",
    )
    assert restored_desc["PipelineExecutionStatus"] == "Succeeded", (
        f"restore: replacing the Deny with an Allow on the IDENTICAL role must let the identical "
        f"call succeed -- proving the block was the policy, not something permanently wrong with "
        f"this role: status={restored_desc['PipelineExecutionStatus']!r} "
        f"reason={restored_desc.get('FailureReason')!r} steps={restored_steps!r}"
    )
    assert _object_exists(s3, bucket, restored_key), (
        f"restore: the now-allowed pipeline reported Succeeded but wrote no object at "
        f"{restored_key!r}"
    )
    restored_written = json.loads(s3.get_object(Bucket=bucket, Key=restored_key)["Body"].read())
    assert restored_written["marker"] == marker, (
        f"restore: the restored step ran with the wrong payload: {restored_written!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
