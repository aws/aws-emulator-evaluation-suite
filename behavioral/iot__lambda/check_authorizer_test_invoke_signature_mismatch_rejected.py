"""authorizer-test-invoke-signature-mismatch-rejected."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-test-invoke-signature-mismatch-rejected"
GROUP = "custom-authorizer"
SERVICES = ["iot", "lambda"]

_HANDLER_CODE = """
import json

def lambda_handler(event, context):
    return {
        "isAuthenticated": True,
        "principalId": "sim2realxsvcprincipal",
        "policyDocuments": [json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Action": "iot:*", "Effect": "Allow", "Resource": "*"}],
        })],
    }
"""


def _error(fn):
    """Call fn(); return the ClientError (code, message).

    Success raises: accepting a signature that does not verify is itself the defect."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a signature-mismatch rejection, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A signing-enabled custom authorizer rejects a token whose signature does not verify
    against its registered public key with InvalidRequestException; the same token signed with
    the registered key authenticates and the backing Lambda's principalId passes through."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    iot = ctx.client("iot")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_arn = _create_lambda_role(ctx, iam)
    fn_name = _create_function(ctx, lam, role_arn)

    registered_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    registered_pub_pem = registered_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    authz_name = ctx.unique_name("sim2real-xsvc-iot-authz-")
    iot.create_authorizer(
        authorizerName=authz_name,
        authorizerFunctionArn=f"arn:aws:lambda:{ctx.region}:{account}:function:{fn_name}",
        status="ACTIVE",
        signingDisabled=False,
        tokenKeyName="token",
        tokenSigningPublicKeys={"Key1": registered_pub_pem},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_authorizer(authorizerName=authz_name))
    ctx.on_cleanup(lambda: iot.update_authorizer(authorizerName=authz_name, status="INACTIVE"))

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="iot-invoke",
        Action="lambda:InvokeFunction",
        Principal="iot.amazonaws.com",
        SourceArn=f"arn:aws:iot:{ctx.region}:{account}:authorizer/{authz_name}",
    )

    token = "allow-me"

    def _sign(private_key):
        sig = private_key.sign(token.encode(), padding.PKCS1v15(), hashes.SHA256())
        return base64.b64encode(sig).decode()

    # Break exactly one thing: sign with a key that was never registered on the authorizer.
    forged_signature = _sign(other_key)
    err = _error(
        lambda: iot.test_invoke_authorizer(
            authorizerName=authz_name, token=token, tokenSignature=forged_signature
        )
    )
    expected = ("InvalidRequestException", f"Token signature mismatch for authorizer {authz_name}")
    assert err == expected, (
        f"expected {expected!r} for an unverifiable signature, got {err!r}"
    )

    # Positive control: the rejection above was about the signature, not the authorizer.
    good_resp = iot.test_invoke_authorizer(
        authorizerName=authz_name, token=token, tokenSignature=_sign(registered_key)
    )
    assert good_resp["isAuthenticated"] is True, (
        f"positive control failed: expected isAuthenticated=True with the registered key's "
        f"signature, got {good_resp.get('isAuthenticated')!r}"
    )
    assert good_resp["principalId"] == "sim2realxsvcprincipal", (
        f"positive control: principalId {good_resp.get('principalId')!r} did not pass through"
    )


def _create_lambda_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-xsvc-iot-authz-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_function(ctx, lam, role_arn):
    name = ctx.unique_name("sim2real-xsvc-iot-authz-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _HANDLER_CODE)
    last_err = None
    for _ in range(10):
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    else:
        raise AssertionError(f"function creation never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _reap_log_group(ctx, fn_name):
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    for _ in range(5):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
