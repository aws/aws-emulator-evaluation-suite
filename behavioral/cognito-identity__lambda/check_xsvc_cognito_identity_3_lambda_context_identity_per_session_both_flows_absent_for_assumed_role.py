"""xsvc-cognito-identity-3-lambda-context-identity-per-session-both-flows-absent-for-assumed-role."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-3-lambda-context-identity-per-session-both-flows-absent-for-assumed-role"
GROUP = "downstream-principal"
SERVICES = ["cognito-identity", "lambda"]

_PROPAGATION_BUDGET_S = 120.0

_HANDLER = '''
def lambda_handler(event, context):
    ident = getattr(context, "identity", None)
    return {
        "nonce": event.get("nonce"),
        "cognito_identity_id": getattr(ident, "cognito_identity_id", None),
        "cognito_identity_pool_id": getattr(ident, "cognito_identity_pool_id", None),
    }
'''


# ===== helpers =====

def _retry(fn, *, retryable, timeout_s, interval_s=3.0, description):
    """Bounded retry over the listed error codes only (IAM / role-mapping propagation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in retryable or time.monotonic() >= deadline:
                raise AssertionError(f"{description} failed: {code!r}: {exc}") from exc
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
    """A client signed with temporary credentials, handed over by value (never os.environ)."""
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
    out = json.loads(body)
    assert out["nonce"] == nonce, f"the function answered nonce {out['nonce']!r}, not {nonce!r}"
    return out


def _invoke_policy(fn_arn):
    return json.dumps({"Version": "2012-10-17",
                       "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction",
                                      "Resource": fn_arn}]})


# ===== check =====

@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda's `context.identity` follows the calling session: classic-flow and enhanced-flow
    Cognito sessions each see their own identity id and pool id (interleaved A, B, A), while a
    plain sts:AssumeRole session with the same invoke grant sees None for both."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    # ---- the function, with an execution role that grants nothing.
    exec_role_name = ctx.unique_name("sim2real-xsvc-ci3-exec-")[:64]
    exec_role_arn = iam.create_role(
        RoleName=exec_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, exec_role_name))

    fn_name = ctx.unique_name("sim2real-xsvc-ci3-fn-")[:64]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _HANDLER)
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

    # ---- an identity pool open to BOTH flows, and its guest role.
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_xsvc_ci3_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        AllowClassicFlow=True,
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
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, guest_role_name))
    iam.put_role_policy(RoleName=guest_role_name, PolicyName="invoke-this-function-only",
                        PolicyDocument=_invoke_policy(fn_arn))
    _retry(lambda: ci.set_identity_pool_roles(IdentityPoolId=pool_id,
                                              Roles={"unauthenticated": guest_role_arn}),
           retryable={"InvalidParameterException", "AccessDeniedException"},
           timeout_s=_PROPAGATION_BUDGET_S, description="SetIdentityPoolRoles")

    # ---- an ORDINARY role this account's principal may assume, with the same invoke grant.
    plain_role_name = ctx.unique_name("sim2real-xsvc-ci3-plain-")[:64]
    plain_role_arn = iam.create_role(
        RoleName=plain_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-3"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, plain_role_name))
    iam.put_role_policy(RoleName=plain_role_name, PolicyName="invoke-this-function-only",
                        PolicyDocument=_invoke_policy(fn_arn))

    # ---- identity A via the classic flow; identity B via the enhanced flow.
    identity_a = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_a]))
    identity_b = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_b]))
    assert identity_a != identity_b, (
        f"two GetId calls minted the same identity {identity_a!r}; nothing below could tell them apart"
    )

    token_a = ci.get_open_id_token(IdentityId=identity_a)
    assert token_a["IdentityId"] == identity_a, (
        f"GetOpenIdToken answered for {token_a['IdentityId']!r}, not {identity_a!r}"
    )
    creds_a = _retry(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=guest_role_arn, RoleSessionName="sim2real-classic",
            WebIdentityToken=token_a["Token"]),
        retryable={"AccessDenied", "InvalidIdentityToken"},
        timeout_s=_PROPAGATION_BUDGET_S, description="AssumeRoleWithWebIdentity (classic flow)",
    )["Credentials"]
    creds_b = _retry(lambda: ci.get_credentials_for_identity(IdentityId=identity_b),
                     retryable={"InvalidIdentityPoolConfigurationException", "AccessDenied",
                                "NotAuthorizedException"},
                     timeout_s=_PROPAGATION_BUDGET_S,
                     description="GetCredentialsForIdentity (enhanced flow)")["Credentials"]
    creds_plain = _retry(
        lambda: sts.assume_role(RoleArn=plain_role_arn, RoleSessionName="sim2real-plain"),
        retryable={"AccessDenied"}, timeout_s=_PROPAGATION_BUDGET_S,
        description="AssumeRole into the ordinary role",
    )["Credentials"]

    lam_a = _client_from_credentials(ctx, "lambda", creds_a)
    lam_b = _client_from_credentials(ctx, "lambda", creds_b)
    lam_plain = _client_from_credentials(ctx, "lambda", creds_plain)

    def _first(lam_client, label):
        return _retry(lambda: _invoke(lam_client, fn_name, uuid.uuid4().hex),
                      retryable={"AccessDeniedException"}, timeout_s=_PROPAGATION_BUDGET_S,
                      description=f"first Invoke with the {label} session")

    # ---- interleaved A, B, A: each session sees only its own identity.
    seen_a = _first(lam_a, "classic-flow")
    seen_b = _first(lam_b, "enhanced-flow")
    seen_a2 = _invoke(lam_a, fn_name, uuid.uuid4().hex)
    for label, seen, want in (("classic A", seen_a, identity_a), ("enhanced B", seen_b, identity_b),
                              ("classic A again", seen_a2, identity_a)):
        assert seen["cognito_identity_id"] == want, (
            f"{label}: context.identity.cognito_identity_id was {seen['cognito_identity_id']!r}, "
            f"expected {want!r}"
        )
        assert seen["cognito_identity_pool_id"] == pool_id, (
            f"{label}: context.identity.cognito_identity_pool_id was "
            f"{seen['cognito_identity_pool_id']!r}, expected {pool_id!r}"
        )

    # ---- negative control: an ordinary assumed-role session carries no Cognito identity.
    seen_plain = _first(lam_plain, "plain AssumeRole")
    assert seen_plain["cognito_identity_id"] is None, (
        f"a plain sts:AssumeRole session's invocation reported cognito_identity_id "
        f"{seen_plain['cognito_identity_id']!r}; it is not a Cognito identity and must see None"
    )
    assert seen_plain["cognito_identity_pool_id"] is None, (
        f"a plain sts:AssumeRole session's invocation reported cognito_identity_pool_id "
        f"{seen_plain['cognito_identity_pool_id']!r}; it must be None"
    )
    # And the invocation right after it, from a Cognito session, still carries its identity.
    seen_b2 = _invoke(lam_b, fn_name, uuid.uuid4().hex)
    assert seen_b2["cognito_identity_id"] == identity_b, (
        f"enhanced B after the plain session reported {seen_b2['cognito_identity_id']!r}, "
        f"expected {identity_b!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
