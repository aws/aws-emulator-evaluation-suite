"""xsvc-iam-2-lambda-remove-permission-revokes-invoke-denied."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-2-lambda-remove-permission-revokes-invoke-denied"
GROUP = "auth_enforcement"
SERVICES = ["iam", "lambda"]

#: Tags that attribute any resource left behind to this check.
_RES_TAGS = [{"Key": "sim2real", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]

_HANDLER = "def handler(event, context):\n    return {\"echo\": event}\n"


# ===== helpers =====
def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _outcome(fn):
    """'OK' when the real signed call succeeds, else its exact AWS error code."""
    code = _error_code(fn)
    return "OK" if code == "UNEXPECTED_SUCCESS" else code


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


#: GetPolicy on a function that carries no resource-based policy.
_NO_POLICY = ("ResourceNotFoundException", "The resource you requested does not exist.")


def _invoke_denied(user_arn, function_arn):
    """The exact refusal of InvokeFunction for a principal no policy grants."""
    return (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: lambda:InvokeFunction on resource: "
        f"{function_arn} because no identity-based policy allows the lambda:InvokeFunction action",
    )


def _settle(probe, want, *, description, streak=3, timeout_s=120, interval_s=2):
    """Poll until probe() returns `want` on `streak` CONSECUTIVE calls.

    IAM is eventually consistent and exposes no API that reports a key or a grant as effective,
    so the operation is its own observable. Settling on the EXACT outcome means a not-yet-live
    access key (UnrecognizedClientException) can never be read as the authorization verdict.
    """
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-12:]!r}"
            )
        time.sleep(interval_s)


def _purge_user(iam, user):
    """Undo everything a check may have hung on a user, then delete it."""
    for fn in (
        lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                 for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
        lambda: [iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]],
        lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                 for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)


def _mint_user(ctx, iam, prefix):
    """A fresh IAM user with NO policy and one access key; returns (name, arn, lambda client as it)."""
    name = ctx.unique_name(prefix)
    arn = iam.create_user(UserName=name, Tags=_RES_TAGS)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, name))
    key = iam.create_access_key(UserName=name)["AccessKey"]
    client = ctx.client("lambda", creds={
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
        "aws_session_token": None,
    })
    return name, arn, client


def _zip(source):
    """A byte-deterministic package: a fixed timestamp, so equal source means equal CodeSha256."""
    info = zipfile.ZipInfo("index.py", date_time=(2020, 1, 1, 0, 0, 0))
    info.external_attr = 0o644 << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(info, source)
    return buf.getvalue()


def _bare_role(ctx, iam, prefix):
    """An execution role Lambda may assume, carrying NO permissions at all.

    No logs permission means the function can never create /aws/lambda/<fn>, so invoking it
    leaves no service-created log group behind to leak.
    """
    name = ctx.unique_name(prefix)
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }), Tags=_RES_TAGS)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_function(ctx, lam, role_arn, prefix):
    """CreateFunction, retrying ONLY the documented new-role propagation refusal, then wait Active."""
    name = ctx.unique_name(prefix)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn,
                                Handler="index.handler", Code={"ZipFile": _zip(_HANDLER)},
                                Timeout=10, Description="sim2real-xsvc-iam-2",
                                Tags={"sim2real": "true", "sim2real:check": CHECK})
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code") == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")
                    and time.monotonic() < deadline):
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name
# ===== end helpers =====


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """RemovePermission revokes only its own statement: that user's Invoke becomes AccessDeniedException
    while a second user's untouched statement keeps working; removing the last statement leaves
    GetPolicy ResourceNotFoundException and the second user refused too."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    first, first_arn, as_first = _mint_user(ctx, iam, "sim2real-xsvc-lam-r1-")
    second, second_arn, as_second = _mint_user(ctx, iam, "sim2real-xsvc-lam-r2-")
    role_arn = _bare_role(ctx, iam, "sim2real-xsvc-lam-rv-")
    fn = _create_function(ctx, lam, role_arn, "sim2real-xsvc-lam-rv-")

    lam.add_permission(FunctionName=fn, StatementId="invoke-first",
                       Action="lambda:InvokeFunction", Principal=first_arn)
    lam.add_permission(FunctionName=fn, StatementId="invoke-second",
                       Action="lambda:InvokeFunction", Principal=second_arn)

    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]
    marker = str(uuid.uuid4())

    def raw_invoke(client):
        return lambda: client.invoke(FunctionName=fn, Payload=json.dumps({"marker": marker}).encode())

    def invoke(client):
        def call():
            resp = client.invoke(FunctionName=fn, Payload=json.dumps({"marker": marker}).encode())
            body = json.loads(resp["Payload"].read())
            assert (resp.get("FunctionError"), body) == (None, {"echo": {"marker": marker}}), (
                f"an authorized Invoke must execute and echo the payload; got {body!r}"
            )
        return _outcome(call)

    # --- Before: both statements present, both users invoke.
    _settle(lambda: invoke(as_first), "OK", description="Invoke by the first user before the revoke")
    _settle(lambda: invoke(as_second), "OK", description="Invoke by the second user before the revoke")

    # --- Revoke ONE statement.
    lam.remove_permission(FunctionName=fn, StatementId="invoke-first")
    _settle(lambda: invoke(as_first), "AccessDeniedException",
            description="Invoke by the first user after RemovePermission of its statement")
    refused = _error(raw_invoke(as_first))
    assert refused == _invoke_denied(first_arn, fn_arn), (
        f"the revoked user's Invoke must be refused with exactly "
        f"{_invoke_denied(first_arn, fn_arn)!r}; got {refused!r}"
    )
    for i in range(3):
        pair = (invoke(as_first), invoke(as_second))
        assert pair == ("AccessDeniedException", "OK"), (
            f"sample {i}: (revoked user, untouched user) were {pair!r}; expected "
            f"('AccessDeniedException', 'OK') -- a revoke must be per-statement"
        )
    stmts = json.loads(lam.get_policy(FunctionName=fn)["Policy"])["Statement"]
    assert [(s["Sid"], s["Principal"]) for s in stmts] == [("invoke-second", {"AWS": second_arn})], (
        f"only the second user's statement may survive the revoke; got {stmts!r}"
    )

    # --- Revoke the last statement: the function has no policy, and the control is refused too.
    lam.remove_permission(FunctionName=fn, StatementId="invoke-second")
    no_policy = _error(lambda: lam.get_policy(FunctionName=fn))
    assert no_policy == _NO_POLICY, (
        f"removing the last statement must leave the function with no resource policy: expected "
        f"{_NO_POLICY!r}, got {no_policy!r}"
    )
    _settle(lambda: invoke(as_second), "AccessDeniedException",
            description="Invoke by the second user after its statement was removed too")
    refused = _error(raw_invoke(as_second))
    assert refused == _invoke_denied(second_arn, fn_arn), (
        f"with no statement left the second user's Invoke must be refused with exactly "
        f"{_invoke_denied(second_arn, fn_arn)!r}; got {refused!r}"
    )
    for u in (first, second):
        assert iam.list_user_policies(UserName=u)["PolicyNames"] == [], f"{u} grew an inline policy"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
