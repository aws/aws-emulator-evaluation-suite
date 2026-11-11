"""identity-policy-grant-on-unqualified-arn-denies-qualified-invoke."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-grant-on-unqualified-arn-denies-qualified-invoke"
GROUP = "auth_enforcement"
SERVICES = ["iam", "lambda", "sts"]

_SRC = "def handler(event, context):\n    return {'ok': True}\n"
_ROLE_NOT_READY = ("InvalidParameterValueException",
                   "The role defined for the function cannot be assumed by Lambda.")
_SESSION = "sim2real-behav-qualified"
_TRUST_LAMBDA = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", _SRC)
    return buf.getvalue()


def _pair(exc: ClientError) -> tuple[str | None, str | None]:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _error(fn) -> tuple[str, str]:
    """(code, message) fn() raises; raises itself when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _function(ctx) -> tuple[str, str]:
    """A tagged function with its own policy-free execution role, Active; returns (name, unqualified ARN)."""
    iam, lam = ctx.client("iam"), ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-qualfn-")
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST_LAMBDA,
                    Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    role_arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = lam.create_function(FunctionName=name, Runtime="python3.12", Handler="index.handler",
                                      Role=role_arn, Code={"ZipFile": _zip()},
                                      Tags={"sim2real": CHECK})["FunctionArn"]
            break
        except ClientError as exc:
            if _pair(exc) != _ROLE_NOT_READY or time.monotonic() >= deadline:
                raise
            time.sleep(4.0)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    deadline = time.monotonic() + 120.0
    while True:
        if lam.get_function_configuration(FunctionName=name).get("State") == "Active":
            return name, arn
        if time.monotonic() >= deadline:
            raise AssertionError(f"function {name} did not become Active within 120s")
        time.sleep(2.0)


def _caller_role(ctx, iam, account, resources: list[str]) -> str:
    """A role the check's own caller (any principal in this account) can assume, holding exactly one inline grant of
    lambda:InvokeFunction scoped to ``resources``; returns its ARN."""
    name = ctx.unique_name("sim2real-behav-qualrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                       "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-invoke"),
                             "NoSuchEntity"))
    _put_invoke_policy(iam, name, resources)
    return role["Arn"]


def _put_invoke_policy(iam, role_name: str, resources: list[str]) -> None:
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": resources}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-invoke", PolicyDocument=json.dumps(policy))


def _assume(ctx, sts, role_arn: str, *, timeout_s: float = 90.0) -> tuple:
    """(lambda client, caller ARN) for an assumed session on ``role_arn``, retried against the
    exact AccessDenied a just-created role answers while its trust propagates."""
    me = sts.get_caller_identity()["Arn"]
    not_yet = ("AccessDenied",
               f"User: {me} is not authorized to perform: sts:AssumeRole on resource: {role_arn}")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            break
        except ClientError as exc:
            if _pair(exc) == not_yet and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise
    creds_kwargs = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    caller_arn = ctx.client("sts", creds=creds_kwargs).get_caller_identity()["Arn"]
    return ctx.client("lambda", creds=creds_kwargs), caller_arn


def _invoke_until_propagated(client, fn: str, not_yet: tuple[str, str], *, qualifier=None,
                             timeout_s=90.0):
    """Invoke, retrying only the exact ``not_yet`` denial while the new inline policy propagates."""
    deadline = time.monotonic() + timeout_s
    kwargs = {"FunctionName": fn, "Payload": b"{}"}
    if qualifier is not None:
        kwargs["Qualifier"] = qualifier
    while True:
        try:
            return client.invoke(**kwargs)
        except ClientError as exc:
            if _pair(exc) == not_yet and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own
    message rather than the runner's."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identity-policy grant of lambda:InvokeFunction on only the unqualified function ARN
    admits an unqualified Invoke but denies one naming a qualified ARN (an alias or a version),
    naming that ARN; adding the function's wildcard qualifier ARN to the grant admits both.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-api-permissions-ref.html
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    lam = ctx.client("lambda")
    account = sts.get_caller_identity()["Account"]

    fn, fn_arn = _function(ctx)
    version = lam.publish_version(FunctionName=fn)["Version"]
    lam.create_alias(FunctionName=fn, Name="live", FunctionVersion=version)
    version_arn = f"{fn_arn}:{version}"
    alias_arn = f"{fn_arn}:live"

    role_arn = _caller_role(ctx, iam, account, [fn_arn])
    caller, caller_arn = _assume(ctx, sts, role_arn, timeout_s=_budget_s(ctx, 90.0))

    def _denied(resource_arn: str) -> tuple[str, str]:
        return (
            "AccessDeniedException",
            f"User: {caller_arn} is not authorized to perform: lambda:InvokeFunction on resource: "
            f"{resource_arn} because no identity-based policy allows the lambda:InvokeFunction action",
        )

    _UNQUALIFIED_DENIED = _denied(fn_arn)
    _VERSION_DENIED = _denied(version_arn)
    _ALIAS_DENIED = _denied(alias_arn)

    # Positive control: the grant on the unqualified ARN admits an unqualified Invoke.
    resp = _invoke_until_propagated(caller, fn, _UNQUALIFIED_DENIED, timeout_s=_budget_s(ctx, 150.0))
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke of the unqualified function under a grant on its unqualified ARN should succeed, "
        f"got StatusCode={resp['StatusCode']!r} FunctionError={resp.get('FunctionError')!r}"
    )

    got = _error(lambda: caller.invoke(FunctionName=fn, Qualifier=version, Payload=b"{}"))
    assert got == _VERSION_DENIED, (
        f"Invoke with Qualifier={version!r} under a grant scoped to the unqualified ARN gave "
        f"{got!r}, expected {_VERSION_DENIED!r}"
    )
    got = _error(lambda: caller.invoke(FunctionName=fn, Qualifier="live", Payload=b"{}"))
    assert got == _ALIAS_DENIED, (
        f"Invoke with Qualifier='live' under a grant scoped to the unqualified ARN gave {got!r}, "
        f"expected {_ALIAS_DENIED!r}"
    )

    # Widen the grant to every qualifier of this function; both qualified calls now admit.
    role_name = role_arn.rsplit("/", 1)[-1]
    _put_invoke_policy(iam, role_name, [fn_arn, f"{fn_arn}:*"])

    resp = _invoke_until_propagated(caller, fn, _VERSION_DENIED, qualifier=version,
                                    timeout_s=_budget_s(ctx, 150.0))
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke with Qualifier={version!r} after widening the grant to {fn_arn}:* should succeed, "
        f"got StatusCode={resp['StatusCode']!r} FunctionError={resp.get('FunctionError')!r}"
    )
    resp = _invoke_until_propagated(caller, fn, _ALIAS_DENIED, qualifier="live",
                                    timeout_s=_budget_s(ctx, 150.0))
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke with Qualifier='live' after widening the grant to {fn_arn}:* should succeed, "
        f"got StatusCode={resp['StatusCode']!r} FunctionError={resp.get('FunctionError')!r}"
    )

    # The unqualified Invoke still succeeds: widening to the qualifier wildcard did not narrow it.
    resp = _invoke_until_propagated(caller, fn, _UNQUALIFIED_DENIED, timeout_s=_budget_s(ctx, 60.0))
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke of the unqualified function must still succeed after widening the grant, got "
        f"StatusCode={resp['StatusCode']!r} FunctionError={resp.get('FunctionError')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
