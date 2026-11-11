"""cli-iam-role-deleted-breaks-lambda-invoke-negative."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import zipfile
from io import BytesIO

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-iam-role-deleted-breaks-lambda-invoke-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Positive control: Invoke succeeds while the function's execution role exists and can
    write to S3. Negative: after the role is deleted (aws iam delete-role), the next Invoke is
    rejected and the marker object for that invocation is never written to S3."""
    require_tools("aws")

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-roledel-")
    _create_bucket(ctx, s3, bucket)

    role_name = ctx.unique_name("sim2real-roledel-role-")
    function_name = ctx.unique_name("sim2real-roledel-fn-")
    policy_name = "s3-write-inline"
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    exec_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"}],
    }
    trust_path = _write_temp_json(trust_policy)
    policy_path = _write_temp_json(exec_policy)
    try:
        role = _run_aws(
            ctx, "iam", "create-role",
            "--role-name", role_name,
            "--assume-role-policy-document", f"file://{trust_path}",
            "--tags", f"Key=sim2real,Value={CHECK}",
        )
        role_arn = role["Role"]["Arn"]

        _run_aws(ctx, "iam", "attach-role-policy", "--role-name", role_name, "--policy-arn", managed_policy_arn)
        _run_aws(
            ctx, "iam", "put-role-policy",
            "--role-name", role_name, "--policy-name", policy_name,
            "--policy-document", f"file://{policy_path}",
        )
    finally:
        os.unlink(trust_path)
        os.unlink(policy_path)

    handler_code = (
        "import os\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    s3 = boto3.client('s3')\n"
        "    s3.put_object(Bucket=os.environ['BUCKET_NAME'], Key=event['key'], Body=b'ok')\n"
        "    return {'wrote': event['key']}\n"
    )
    zip_path = _write_zip(handler_code)
    try:
        create_args = [
            "lambda", "create-function",
            "--function-name", function_name,
            "--runtime", "python3.12",
            "--role", role_arn,
            "--handler", "index.handler",
            "--zip-file", f"fileb://{zip_path}",
            "--timeout", "30",
            "--environment", f"Variables={{BUCKET_NAME={bucket}}}",
            "--tags", f"sim2real={CHECK}",
        ]
        _create_function_with_role_propagation_retry(ctx, create_args)
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "lambda", "delete-function", "--function-name", function_name], check=False,
        ))
    finally:
        os.unlink(zip_path)

    _poll_until(
        lambda: _run_aws(ctx, "lambda", "get-function-configuration",
                          "--function-name", function_name).get("State"),
        lambda state: state == "Active",
        timeout_s=60, interval_s=2,
    )

    # Positive control: invoke succeeds and actually writes the marker object while the role exists.
    before_key = "before-delete.txt"
    _invoke(ctx, function_name, {"key": before_key}, expect_success=True)
    obj = _poll_until(
        lambda: _try_get_object(s3, bucket, before_key),
        lambda o: o is not None,
        timeout_s=30, interval_s=2,
    )
    assert obj is not None, (
        f"positive control failed: {before_key!r} was never written to {bucket!r} while the "
        f"execution role still existed"
    )

    # Break exactly one thing: remove the execution role entirely.
    _run_aws(ctx, "iam", "delete-role-policy", "--role-name", role_name, "--policy-name", policy_name)
    _run_aws(ctx, "iam", "detach-role-policy", "--role-name", role_name, "--policy-arn", managed_policy_arn)
    _run_aws(ctx, "iam", "delete-role", "--role-name", role_name)

    _poll_until(
        lambda: _run_shell(ctx, ["aws", "iam", "get-role", "--role-name", role_name], check=False).returncode,
        lambda rc: rc != 0,
        timeout_s=30, interval_s=2,
    )

    # Force a fresh execution environment (a warm sandbox can keep using previously-issued
    # credentials for a while after the role is gone) so the next Invoke must re-assume the role.
    _run_aws(
        ctx, "lambda", "update-function-configuration",
        "--function-name", function_name, "--description", "force-new-execution-environment",
    )
    _poll_until(
        lambda: _run_aws(ctx, "lambda", "get-function-configuration",
                          "--function-name", function_name).get("LastUpdateStatus"),
        lambda status: status == "Successful",
        timeout_s=30, interval_s=2,
    )

    after_key = "after-delete.txt"
    # The fresh execution environment still starts, and S3 refuses the function's PutObject. AWS
    # answers either way depending on how far the deleted role's session has been revoked:
    # the session's access key is already unknown, or the session survives without the
    # deleted role's policies.
    code, message, refused_key = _invoke_until_denied(
        ctx, function_name, after_key, timeout_s=90.0, interval_s=3.0
    )
    if code == "InvalidAccessKeyId":
        assert message == (
            "An error occurred (InvalidAccessKeyId) when calling the PutObject operation: "
            "The AWS Access Key Id you provided does not exist in our records."
        ), f"unexpected InvalidAccessKeyId message: {message!r}"
    elif code == "AccessDenied":
        partition, account = role_arn.split(":")[1], role_arn.split(":")[4]
        expected = (
            f"An error occurred (AccessDenied) when calling the PutObject operation: User: "
            f"arn:{partition}:sts::{account}:assumed-role/{role_name}/{function_name} is not "
            f"authorized to perform: s3:PutObject on resource: "
            f'"arn:{partition}:s3:::{bucket}/{refused_key}" because no identity-based policy allows '
            f"the s3:PutObject action"
        )
        assert message == expected, f"unexpected AccessDenied message: {message!r}"
    else:
        raise AssertionError(
            f"expected the function's PutObject to be refused once the role is gone, got {code}: {message!r}"
        )

    # Effect-absent: the marker object for the rejected invocation was never written.
    assert _try_get_object(s3, bucket, refused_key) is None, (
        f"expected no marker object at {refused_key!r} in {bucket!r} once the execution role was "
        f"gone, but one was found"
    )

    # Restore: recreate the execution role under the same name and policies, point the function
    # back at it, and demand the identical Invoke succeed again -- proving the earlier rejection
    # tracked the role's existence specifically, and not some other break.
    trust_path = _write_temp_json(trust_policy)
    policy_path = _write_temp_json(exec_policy)
    try:
        role = _run_aws(
            ctx, "iam", "create-role",
            "--role-name", role_name,
            "--assume-role-policy-document", f"file://{trust_path}",
            "--tags", f"Key=sim2real,Value={CHECK}",
        )
        role_arn = role["Role"]["Arn"]
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "iam", "delete-role", "--role-name", role_name], check=False,
        ))
        _run_aws(ctx, "iam", "attach-role-policy", "--role-name", role_name, "--policy-arn", managed_policy_arn)
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "iam", "detach-role-policy",
                  "--role-name", role_name, "--policy-arn", managed_policy_arn], check=False,
        ))
        _run_aws(
            ctx, "iam", "put-role-policy",
            "--role-name", role_name, "--policy-name", policy_name,
            "--policy-document", f"file://{policy_path}",
        )
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "iam", "delete-role-policy",
                  "--role-name", role_name, "--policy-name", policy_name], check=False,
        ))
    finally:
        os.unlink(trust_path)
        os.unlink(policy_path)

    _update_function_role_with_propagation_retry(ctx, function_name, role_arn)
    _poll_until(
        lambda: _run_aws(ctx, "lambda", "get-function-configuration",
                          "--function-name", function_name).get("LastUpdateStatus"),
        lambda status: status == "Successful",
        timeout_s=30, interval_s=2,
    )

    restored_key = "after-restore.txt"
    _invoke_until_success(ctx, function_name, restored_key, timeout_s=90.0, interval_s=3.0)
    restored_obj = _poll_until(
        lambda: _try_get_object(s3, bucket, restored_key),
        lambda o: o is not None,
        timeout_s=30, interval_s=2,
    )
    assert restored_obj is not None, (
        f"expected the identical Invoke to succeed once the execution role was recreated and "
        f"reattached, but the marker object {restored_key!r} was never written to {bucket!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _write_temp_json(obj) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    return path


def _write_zip(handler_source: str) -> str:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_source)
    fd, path = tempfile.mkstemp(suffix=".zip")
    with os.fdopen(fd, "wb") as f:
        f.write(buf.getvalue())
    return path


def _create_bucket(ctx, s3, bucket: str) -> None:
    # CreateBucket rejects an explicit LocationConstraint for us-east-1 specifically; the region
    # literal here tracks that S3 API quirk, not a pin of the check itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _try_get_object(s3, bucket, key):
    from botocore.exceptions import ClientError
    try:
        return s3.get_object(Bucket=bucket, Key=key)
    except ClientError:
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_function_with_role_propagation_retry(ctx, create_args, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, ["aws", "--output", "json", *create_args], check=False)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_err = proc.stderr
        if "InvalidParameterValueException" in proc.stderr and "assumed" in proc.stderr:
            time.sleep(interval_s)
            continue
        raise AssertionError(f"create-function failed: {last_err[-500:]}")
    raise AssertionError(f"create-function never succeeded after role propagation wait: {last_err[-500:]}")


def _update_function_role_with_propagation_retry(ctx, function_name, role_arn, *, timeout_s=90.0, interval_s=3.0):
    """UpdateFunctionConfiguration validates AssumeRole synchronously, so a just-(re)created role
    hits the same propagation delay CreateFunction does in
    _create_function_with_role_propagation_retry."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = ""
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx,
            ["aws", "--output", "json", "lambda", "update-function-configuration",
             "--function-name", function_name, "--role", role_arn],
            check=False,
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_err = proc.stderr
        if "InvalidParameterValueException" in proc.stderr and "assumed" in proc.stderr:
            time.sleep(interval_s)
            continue
        raise AssertionError(f"update-function-configuration --role failed: {last_err[-500:]}")
    raise AssertionError(
        f"update-function-configuration --role never succeeded after role propagation wait: {last_err[-500:]}"
    )


def _cli_error_code(stderr: str):
    m = re.search(r"An error occurred \(([A-Za-z0-9]+)\)", stderr)
    return m.group(1) if m else None


def _invoke_until_denied(ctx, function_name, key, *, timeout_s=90.0, interval_s=3.0):
    """Retry the Invoke until it is rejected — either because the synchronous Invoke API call
    itself is rejected (CLI-level error), or because Lambda accepts the call but the function's
    own AWS SDK call fails inside the execution environment once the assumed-role credentials
    backing that environment are no longer valid (a warm execution environment can keep using
    previously-issued sts credentials for a short window after the execution role is deleted, so
    a single immediate Invoke can spuriously still "succeed" at the CLI level). Returns the
    refusal's (code, message, key of the refused attempt)."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_code = None
    last_returncode = None
    attempt = 0
    while time.monotonic() < deadline:
        # each attempt writes its own key, so an early attempt that still succeeds leaves no
        # marker under the key of the attempt that is refused
        attempt += 1
        attempt_key = f"{attempt}-{key}"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
            json.dump({"key": attempt_key}, pf)
            payload_path = pf.name
        out_path = payload_path + ".out"
        try:
            proc = _run_shell(
                ctx,
                ["aws", "--output", "json", "lambda", "invoke",
                 "--function-name", function_name,
                 "--payload", f"file://{payload_path}",
                 "--cli-binary-format", "raw-in-base64-out",
                 out_path],
                check=False,
            )
            last_returncode = proc.returncode
            if proc.returncode != 0:
                last_code = _cli_error_code(proc.stderr)
                if last_code == "AccessDeniedException":
                    return last_code, proc.stderr.strip(), attempt_key
            else:
                # The synchronous call succeeded; check whether the function itself failed
                # because its execution-environment credentials are now dangling (the role
                # behind them was deleted).
                with open(out_path) as f:
                    result = json.load(f)
                if isinstance(result, dict) and "errorMessage" in result:
                    msg = result["errorMessage"]
                    m = re.match(r"An error occurred \(([A-Za-z0-9]+)\)", msg)
                    if m:
                        return m.group(1), msg, attempt_key
                    last_code = f"invoke-errored:{msg}"
                else:
                    last_code = f"invoke-succeeded:{result!r}"
        finally:
            os.unlink(payload_path)
            if os.path.exists(out_path):
                os.unlink(out_path)
        time.sleep(interval_s)
    raise AssertionError(
        f"invoke never failed (CLI-level or in-function credential error) within {timeout_s}s "
        f"(last_returncode={last_returncode}, last_code={last_code!r})"
    )


def _invoke_until_success(ctx, function_name, key, *, timeout_s=90.0, interval_s=3.0):
    """Retry the Invoke until it succeeds. A freshly (re)created role's trust policy needs time
    to propagate before Lambda can assume it, mirroring _create_function_with_role_propagation_retry
    and _invoke_until_denied's own retry for the opposite direction."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_detail = None
    while time.monotonic() < deadline:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
            json.dump({"key": key}, pf)
            payload_path = pf.name
        out_path = payload_path + ".out"
        try:
            proc = _run_shell(
                ctx,
                ["aws", "--output", "json", "lambda", "invoke",
                 "--function-name", function_name,
                 "--payload", f"file://{payload_path}",
                 "--cli-binary-format", "raw-in-base64-out",
                 out_path],
                check=False,
            )
            if proc.returncode == 0:
                with open(out_path) as f:
                    result = json.load(f)
                if result == {"wrote": key}:
                    return result
                last_detail = f"invoke-succeeded-but-unexpected-result:{result!r}"
            else:
                last_detail = f"invoke-failed:{_cli_error_code(proc.stderr)}"
        finally:
            os.unlink(payload_path)
            if os.path.exists(out_path):
                os.unlink(out_path)
        time.sleep(interval_s)
    raise AssertionError(
        f"invoke never succeeded within {timeout_s}s after the execution role was recreated and "
        f"reattached (last={last_detail!r})"
    )


def _invoke(ctx, function_name, payload, *, expect_success: bool):
    """Invoke via the CLI. If expect_success, returns the parsed payload and asserts no
    FunctionError. If not, returns the CLI-reported error code (asserting the call itself
    failed, since a role that cannot be assumed rejects the Invoke API call synchronously)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
        json.dump(payload, pf)
        payload_path = pf.name
    out_path = payload_path + ".out"
    try:
        proc = _run_shell(
            ctx,
            ["aws", "--output", "json", "lambda", "invoke",
             "--function-name", function_name,
             "--payload", f"file://{payload_path}",
             "--cli-binary-format", "raw-in-base64-out",
             out_path],
            check=False,
        )
        if expect_success:
            assert proc.returncode == 0, f"expected successful invoke, got: {proc.stderr[-500:]}"
            with open(out_path) as f:
                result = json.load(f)
            assert result == {"wrote": payload["key"]}, f"unexpected invoke result: {result}"
            return result
        assert proc.returncode != 0, "expected invoke to fail once the execution role was deleted"
        return _cli_error_code(proc.stderr)
    finally:
        os.unlink(payload_path)
        if os.path.exists(out_path):
            os.unlink(out_path)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
