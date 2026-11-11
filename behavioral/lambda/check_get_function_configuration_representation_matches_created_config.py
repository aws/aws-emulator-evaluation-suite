"""get-function-configuration-representation-matches-created-config."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-function-configuration-representation-matches-created-config"
GROUP = "server-side"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFunction's MemorySize, Timeout, Environment, Architectures and Description round-trip
    exactly in GetFunctionConfiguration, and PublishVersion yields a numbered version with its own
    ARN and the same CodeSha256; an unknown qualifier raises ResourceNotFoundException."""
    lam = ctx.client("lambda")
    exec_role_arn = _create_exec_role(ctx)

    fn_name = ctx.unique_name("sim2real-repr-fn-")
    env_vars = {"SIM2REAL_KEY": "sim2real-value", "SIM2REAL_OTHER": "42"}
    _create_function_with_retry(
        ctx,
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=exec_role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": _lambda_zip_bytes()},
        Timeout=45,
        MemorySize=256,
        Architectures=["arm64"],
        Description="sim2real representation probe",
        Environment={"Variables": env_vars},
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    cfg = _wait_function_active(ctx, fn_name, timeout_s=120.0)

    # Representation of $LATEST must echo every input field exactly, not a subset.
    assert cfg["FunctionName"] == fn_name, (fn_name, cfg["FunctionName"])
    assert cfg["Timeout"] == 45, cfg["Timeout"]
    assert cfg["MemorySize"] == 256, cfg["MemorySize"]
    assert cfg["Architectures"] == ["arm64"], cfg["Architectures"]
    assert cfg["Description"] == "sim2real representation probe", cfg["Description"]
    assert cfg["Environment"]["Variables"] == env_vars, cfg["Environment"]["Variables"]
    assert cfg["Version"] == "$LATEST", cfg["Version"]
    assert cfg["FunctionArn"].endswith(fn_name), cfg["FunctionArn"]
    assert "CodeSha256" in cfg and cfg["CodeSha256"], cfg
    assert "RevisionId" in cfg and cfg["RevisionId"], cfg
    latest_sha = cfg["CodeSha256"]
    latest_revision = cfg["RevisionId"]

    # PublishVersion must yield its OWN numbered representation, distinct from
    # $LATEST's, with the same code (same hash) but a different Version/ARN/revision.
    published = lam.publish_version(FunctionName=fn_name)
    version = published["Version"]
    assert version != "$LATEST", version
    assert published["CodeSha256"] == latest_sha, (published["CodeSha256"], latest_sha)
    assert published["FunctionArn"].endswith(f":{fn_name}:{version}"), (published["FunctionArn"], fn_name, version)
    assert published["RevisionId"] != latest_revision, "published version reused $LATEST's revision id"

    versioned_cfg = lam.get_function_configuration(FunctionName=fn_name, Qualifier=version)
    assert versioned_cfg["Version"] == version, versioned_cfg["Version"]
    assert versioned_cfg["MemorySize"] == 256, versioned_cfg["MemorySize"]
    assert versioned_cfg["Environment"]["Variables"] == env_vars, versioned_cfg["Environment"]["Variables"]
    assert versioned_cfg["FunctionArn"] == published["FunctionArn"], (versioned_cfg["FunctionArn"], published["FunctionArn"])

    # Overly-permissive guard: an unknown qualifier on a real function must be
    # rejected with ResourceNotFoundException, not silently fall back to $LATEST.
    bogus_qualifier = "999999"
    code, msg = _client_error(lambda: lam.get_function_configuration(FunctionName=fn_name, Qualifier=bogus_qualifier))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_msg = f"Function not found: {cfg['FunctionArn']}:{bogus_qualifier}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """(code, message) of a call that must be refused; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "lambda_function.py",
            "def lambda_handler(event, context):\n    return {'ok': True}\n",
        )
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-repr-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    return role_arn


def _create_function_with_retry(ctx, timeout_s: float = 30.0, **kwargs) -> dict:
    """CreateFunction can reject a just-created role until IAM propagation catches
    up; retry on that specific, transient condition rather than a bare sleep."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"create_function never succeeded within {timeout_s}s: {last_exc}")


def _wait_function_active(ctx, name: str, timeout_s: float = 120.0) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        last_state = cfg["State"]
        if last_state == "Active":
            return cfg
        if last_state == "Failed":
            raise AssertionError(f"function {name} entered Failed state: {cfg}")
        time.sleep(3)
    raise AssertionError(f"function {name} never reached Active (last={last_state}) within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

