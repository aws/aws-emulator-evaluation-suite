"""xsvc-cognito-identity-3-lambda-context-carries-the-vended-identity-and-none-for-an-iam-caller."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-3-lambda-context-carries-the-vended-identity-and-none-for-an-iam-caller"
GROUP = "downstream-principal"
SERVICES = ["cognito-identity", "lambda"]

_PROPAGATION_BUDGET_S = 120.0
_DENIED_CODE = "AccessDeniedException"

# The function reports exactly what the Lambda runtime put on `context.identity`, plus the nonce it
# was sent, so the caller can tell "this invocation" from any other. It has no logs permission at
# all (its execution role carries no policy), so it never materialises a /aws/lambda/ log group
# that could outlive the check.
_HANDLER = '''
import json

def lambda_handler(event, context):
    ident = getattr(context, "identity", None)
    return {
        "nonce": event.get("nonce"),
        "identity_present": ident is not None,
        "cognito_identity_id": getattr(ident, "cognito_identity_id", None),
        "cognito_identity_pool_id": getattr(ident, "cognito_identity_pool_id", None),
    }
'''


def _error(fn):
    """Call fn(); return the error (code, message). An unexpected SUCCESS raises: an emulator
    accepting a call real AWS refuses is the strongest signal there is and must not read as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _retry(fn, *, retryable, timeout_s, interval_s=3.0, description):
    """Bounded retry over the listed error codes only (IAM / role-mapping propagation)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in retryable or time.monotonic() >= deadline:
                raise AssertionError(f"{description} failed: {code!r}: {exc}") from exc
            last = exc
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _delete_role(iam, role_name):
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _delete_log_group_if_any(ctx, fn_name):
    """The execution role has no logs permission, so the group should never exist; delete it if
    the service made one anyway; any failure other than not-found raises."""
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise RuntimeError(
                f"/aws/lambda/{fn_name} could not be deleted: {exc!r}"
            ) from exc


def _client_from_credentials(ctx, service, creds):
    """A client on the target signed with vended temporary credentials, never os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _invoke(lam, fn_name, nonce):
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse",
                      Payload=json.dumps({"nonce": nonce}).encode())
    body = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"invoke returned StatusCode {resp['StatusCode']!r}: {body!r}"
    assert "FunctionError" not in resp, (
        f"the function itself raised ({resp['FunctionError']!r}): {body!r}"
    )
    return json.loads(body)


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda invoked with Cognito-vended guest credentials sees that identity id and pool id on
    context.identity, an IAM caller sees None for both, and the vended session is refused
    GetFunction with AccessDeniedException because its role allows only the invoke.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    # ---- the function, with an execution role that grants nothing (no logs, nothing else).
    exec_role_name = ctx.unique_name("sim2real-xsvc-ci3-exec-")[:64]
    exec_role_arn = iam.create_role(
        RoleName=exec_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, exec_role_name))

    fn_name = ctx.unique_name("sim2real-xsvc-ci3-fn-")[:64]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _HANDLER)
    # Registered before the create so LIFO runs it after delete_function.
    ctx.on_cleanup(lambda: _delete_log_group_if_any(ctx, fn_name))
    fn_arn = _retry(
        lambda: lam.create_function(
            FunctionName=fn_name, Runtime="python3.12", Role=exec_role_arn,
            Handler="lambda_function.lambda_handler", Code={"ZipFile": buf.getvalue()},
            Timeout=15, MemorySize=128, Tags={"sim2real": "xsvc-cognito-identity-3"},
        ),
        retryable={"InvalidParameterValueException"},
        timeout_s=_PROPAGATION_BUDGET_S,
        description="CreateFunction through the execution-role propagation window",
    )["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=fn_name)["State"],
                lambda s: s == "Active", timeout_s=120, description=f"function {fn_name} Active")

    # ---- the identity pool, a guest identity, and the role its mapping assumes.
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_xsvc_ci3_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": "xsvc-cognito-identity-3"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    guest_role_name = ctx.unique_name("sim2real-xsvc-ci3-guest-")[:64]
    guest_role_arn = iam.create_role(
        RoleName=guest_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
                },
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, guest_role_name))
    iam.put_role_policy(
        RoleName=guest_role_name, PolicyName="invoke-this-function-only",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction",
                           "Resource": fn_arn}],
        }),
    )
    _retry(lambda: ci.set_identity_pool_roles(IdentityPoolId=pool_id,
                                              Roles={"unauthenticated": guest_role_arn}),
           retryable={"InvalidParameterException", "AccessDeniedException"},
           timeout_s=_PROPAGATION_BUDGET_S, description="SetIdentityPoolRoles")

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    assert identity_id.startswith(f"{ctx.region}:"), (
        f"GetId returned {identity_id!r}, which is not a {ctx.region}-scoped identity id"
    )

    creds = _retry(lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
                   retryable={"InvalidIdentityPoolConfigurationException", "AccessDenied",
                              "NotAuthorizedException"},
                   timeout_s=_PROPAGATION_BUDGET_S,
                   description="GetCredentialsForIdentity")
    assert creds["IdentityId"] == identity_id, (
        f"credentials were vended for {creds['IdentityId']!r}, not the GetId identity {identity_id!r}"
    )
    vended_lam = _client_from_credentials(ctx, "lambda", creds["Credentials"])

    # ---- positive: the vended principal invokes, and the runtime context names its identity.
    nonce_vended = uuid.uuid4().hex
    out = _retry(lambda: _invoke(vended_lam, fn_name, nonce_vended),
                 retryable={_DENIED_CODE}, timeout_s=_PROPAGATION_BUDGET_S,
                 description="Invoke with the vended guest credentials")
    assert out["nonce"] == nonce_vended, (
        f"the function answered nonce {out['nonce']!r}, not this invocation's {nonce_vended!r}"
    )
    assert out["cognito_identity_id"] == identity_id, (
        f"context.identity.cognito_identity_id inside the function was "
        f"{out['cognito_identity_id']!r}; GetId minted {identity_id!r}"
    )
    assert out["cognito_identity_pool_id"] == pool_id, (
        f"context.identity.cognito_identity_pool_id inside the function was "
        f"{out['cognito_identity_pool_id']!r}; the pool is {pool_id!r}"
    )

    # ---- negative control: a plain IAM caller invoking the SAME function carries no identity.
    nonce_iam = uuid.uuid4().hex
    out_iam = _invoke(lam, fn_name, nonce_iam)
    assert out_iam["nonce"] == nonce_iam, (
        f"the IAM-caller invocation answered nonce {out_iam['nonce']!r}, not {nonce_iam!r}"
    )
    assert out_iam["cognito_identity_id"] is None, (
        f"a plain IAM caller's invocation reported cognito_identity_id "
        f"{out_iam['cognito_identity_id']!r}; it must be None — the target is stamping an identity "
        f"the caller never presented"
    )
    assert out_iam["cognito_identity_pool_id"] is None, (
        f"a plain IAM caller's invocation reported cognito_identity_pool_id "
        f"{out_iam['cognito_identity_pool_id']!r}; it must be None"
    )

    # ---- and the vended session is bounded by its role: invoke only, not GetFunction.
    code, message = _error(lambda: vended_lam.get_function(FunctionName=fn_name))
    assert code == _DENIED_CODE, (
        f"GetFunction with the vended guest credentials (role grants lambda:InvokeFunction only) "
        f"returned {code!r}: {message!r}; expected {_DENIED_CODE!r}"
    )
    session_arn = (
        f"arn:aws:sts::{ctx.account}:assumed-role/{guest_role_name}/CognitoIdentityCredentials"
    )
    expected = (
        f"User: {session_arn} is not authorized to perform: lambda:GetFunction on resource: "
        f"{fn_arn} because no identity-based policy allows the lambda:GetFunction action"
    )
    assert message == expected, f"GetFunction refusal: expected {expected!r}, got {message!r}"
    # A second vended invoke after the refusal still carries the same identity: the refusal did not
    # come from a broken session.
    again = _invoke(vended_lam, fn_name, "again")
    assert again["cognito_identity_id"] == identity_id, (
        f"a repeat vended invocation reported {again['cognito_identity_id']!r}, expected {identity_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
