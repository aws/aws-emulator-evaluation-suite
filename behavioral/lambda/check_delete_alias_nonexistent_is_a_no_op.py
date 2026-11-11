"""delete-alias-nonexistent-is-a-no-op."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-alias-nonexistent-is-a-no-op"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlias of a never-created or already-deleted alias name succeeds as a no-op, even with a
    real alias present, and leaves that unrelated alias untouched.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_DeleteAlias.html
    """
    lam = ctx.client("lambda")
    fn = _create_function(ctx)

    version = lam.publish_version(FunctionName=fn["name"])["Version"]
    lam.create_alias(
        FunctionName=fn["name"], Name="real-alias", FunctionVersion=version
    )

    def _delete_alias_tolerant(name):
        deadline = time.monotonic() + 60
        delay = 2.0
        while True:
            try:
                lam.delete_alias(FunctionName=fn["name"], Name=name)
                return None
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if (
                    code
                    in (
                        "ServiceException",
                        "TooManyRequestsException",
                        "ResourceConflictException",
                    )
                    and time.monotonic() < deadline
                ):
                    time.sleep(delay)
                    delay = min(delay * 1.5, 15.0)
                    continue
                return code

    error_code = _delete_alias_tolerant("does-not-exist")
    assert error_code is None, (
        f"expected DeleteAlias of a never-created name to succeed as a no-op, got {error_code!r}"
    )

    error_code_again = _delete_alias_tolerant("does-not-exist")
    assert error_code_again is None, (
        f"expected the repeat delete-of-nonexistent-alias to also succeed as a no-op, "
        f"got {error_code_again!r}"
    )

    still_there = lam.get_alias(FunctionName=fn["name"], Name="real-alias")
    assert still_there["FunctionVersion"] == version, (
        "the real alias's target version changed after deleting an unrelated, never-created name"
    )
    lam.delete_alias(FunctionName=fn["name"], Name="real-alias")
    alias_missing_msg = f"Cannot find alias arn: {fn['arn']}:real-alias"

    try:
        gone = lam.get_alias(FunctionName=fn["name"], Name="real-alias")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected the deleted real alias to read back as ResourceNotFoundException, "
            f"got {e.response['Error']['Code']!r}"
        )
        assert e.response["Error"].get("Message") == alias_missing_msg, (
            f"expected the not-found message {alias_missing_msg!r}, "
            f"got {e.response['Error'].get('Message')!r}"
        )
    else:
        raise AssertionError(
            f"expected the deleted real alias to be gone, but get_alias still returned it: {gone!r}"
        )

    error_code_after_real_delete = _delete_alias_tolerant("real-alias")
    assert error_code_after_real_delete is None, (
        f"expected DeleteAlias of an alias that was just deleted to also succeed as a no-op, "
        f"got {error_code_after_real_delete!r}"
    )

    try:
        still_gone = lam.get_alias(FunctionName=fn["name"], Name="real-alias")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected the alias to remain gone after the repeat no-op delete, "
            f"got {e.response['Error']['Code']!r}"
        )
        assert e.response["Error"].get("Message") == alias_missing_msg, (
            f"expected the not-found message {alias_missing_msg!r}, "
            f"got {e.response['Error'].get('Message')!r}"
        )
    else:
        raise AssertionError(
            f"the repeat no-op delete of an already-deleted alias resurrected it: {still_gone!r}"
        )


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def handler(event, context):\n    return {'ok': True}\n",
        )
    return buf.getvalue()


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_active(lam, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(
                f"function entered Failed state: {cfg.get('StateReason')}"
            )
        time.sleep(2)
    raise AssertionError("function did not become Active in time")


def _create_function(ctx, **overrides):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    role_arn = _create_lambda_role(ctx)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _minimal_zip_bytes()},
        Timeout=10,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    kwargs.update(overrides)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"][
                "Code"
            ] == "InvalidParameterValueException" and "cannot be assumed" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(lam, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
