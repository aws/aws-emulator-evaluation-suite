"""authorizer-signed-token-either-key-passthrough."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "authorizer-signed-token-either-key-passthrough"
GROUP = "custom-authorizer"
SERVICES = ["iot", "lambda"]

_HANDLER_CODE = """
import json

def lambda_handler(event, context):
    return {
        "isAuthenticated": True,
        "principalId": "sim2realxsvcprincipal",
        "disconnectAfterInSeconds": 86400,
        "refreshAfterInSeconds": 300,
        "policyDocuments": [json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Action": "iot:*", "Effect": "Allow", "Resource": "*"}],
        })],
    }
"""


@tags(
    "axis:happy-path", "cap:c3", "cap:c7", "concern:e2e", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A signing-enabled custom authorizer with two public keys accepts a token signed by either
    key, and TestInvokeAuthorizer returns the Lambda's principalId, policyDocuments and both TTLs.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    iot = ctx.client("iot")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_arn = _create_lambda_role(ctx, iam)
    fn_name = _create_function(ctx, lam, role_arn)

    key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub1_pem = key1.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    pub2_pem = key2.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    authz_name = ctx.unique_name("sim2real-xsvc-iot-authz-")
    iot.create_authorizer(
        authorizerName=authz_name,
        authorizerFunctionArn=f"arn:aws:lambda:{ctx.region}:{account}:function:{fn_name}",
        status="ACTIVE",
        signingDisabled=False,
        tokenKeyName="token",
        tokenSigningPublicKeys={"Key1": pub1_pem, "Key2": pub2_pem},
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

    for label, key in (("Key1", key1), ("Key2", key2)):
        resp = iot.test_invoke_authorizer(
            authorizerName=authz_name, token=token, tokenSignature=_sign(key)
        )
        assert resp["isAuthenticated"] is True, (
            f"{label}: expected isAuthenticated=True with a signature made by a registered key, "
            f"got {resp.get('isAuthenticated')!r}"
        )
        assert resp["principalId"] == "sim2realxsvcprincipal", (
            f"{label}: principalId {resp.get('principalId')!r} did not pass through unchanged "
            "from the Lambda's response"
        )
        assert resp["policyDocuments"] == [
            json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Action": "iot:*", "Effect": "Allow", "Resource": "*"}],
            })
        ], f"{label}: policyDocuments {resp.get('policyDocuments')!r} did not match the Lambda's output"
        assert resp["refreshAfterInSeconds"] == 300, (
            f"{label}: refreshAfterInSeconds {resp.get('refreshAfterInSeconds')!r} != 300"
        )
        assert resp["disconnectAfterInSeconds"] == 86400, (
            f"{label}: disconnectAfterInSeconds {resp.get('disconnectAfterInSeconds')!r} != 86400"
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
    from botocore.exceptions import ClientError

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
