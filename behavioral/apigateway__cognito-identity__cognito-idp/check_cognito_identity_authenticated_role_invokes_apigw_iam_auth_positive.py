"""cognito-identity-authenticated-role-invokes-apigw-iam-auth-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cognito-identity-authenticated-role-invokes-apigw-iam-auth-positive"
GROUP = "event-propagation"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Temporary credentials from Identity Pool federation SigV4-sign and successfully
    invoke an IAM-authorized API Gateway method, end to end through the deployed stage."""
    api = _create_mock_iam_api(ctx)
    pool = _create_confirmed_user_pool(ctx, "sim2real-uidp3-")
    identity_pool_id = _create_identity_pool(
        ctx,
        "sim2real-ip3-",
        providers=[
            {
                "ProviderName": pool["provider_name"],
                "ClientId": pool["client_id"],
                "ServerSideTokenCheck": False,
            }
        ],
    )
    role = _create_federated_role(ctx, identity_pool_id, amr="authenticated")
    _attach_invoke_policy(ctx, role["name"], api["method_arn"])

    cid = ctx.client("cognito-identity")
    cid.set_identity_pool_roles(
        IdentityPoolId=identity_pool_id, Roles={"authenticated": role["arn"]}
    )

    logins = {pool["provider_name"]: pool["id_token"]}
    identity_id = cid.get_id(IdentityPoolId=identity_pool_id, Logins=logins)["IdentityId"]
    creds = _get_credentials_with_retry(ctx, identity_id, logins)["Credentials"]

    status, body = _poll_apigw_until(
        lambda: _invoke_apigw_iam(ctx, api["url"], creds), expected_status=200, timeout_s=90.0
    )
    assert status == 200, f"expected the SigV4-signed call to reach 200, got {status}: {body!r}"
    parsed = json.loads(body)
    assert parsed == {"message": "ok"}, f"expected the mock integration body, got {parsed!r}"


def _create_confirmed_user_pool(ctx, name_prefix: str) -> dict:
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name(name_prefix)
    pool_id = idp.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real": CHECK}
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=pool_name + "-client",
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("user-")
    password = "Sim2Real1!Aa"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return {
        "pool_id": pool_id,
        "client_id": client_id,
        "username": username,
        "id_token": id_token,
        "provider_name": provider_name,
    }


def _create_identity_pool(ctx, name_prefix: str, providers=None, allow_unauth: bool = False) -> str:
    cid = ctx.client("cognito-identity")
    name = ctx.unique_name(name_prefix)
    pool_id = cid.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        CognitoIdentityProviders=providers or [],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_federated_role(ctx, identity_pool_id: str, amr: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cidp-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": identity_pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return {"name": role_name, "arn": role_arn}


def _attach_invoke_policy(ctx, role_name: str, method_arn: str) -> None:
    iam = ctx.client("iam")
    policy_name = "invoke-execute-api"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": method_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_mock_iam_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-api-")
    api_id = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="AWS_IAM"
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "ok"}'},
    )
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    url = _apigw_url(ctx, api_id, stage_name, "widgets")
    method_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/{stage_name}/GET/widgets"
    return {"api_id": api_id, "url": url, "method_arn": method_arn, "account_id": account_id}


def _apigw_url(ctx, api_id: str, stage: str, path: str = "") -> str:
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _invoke_apigw_iam(ctx, url: str, creds: dict, method: str = "GET"):
    credentials = Credentials(creds["AccessKeyId"], creds["SecretKey"], creds["SessionToken"])
    request = AWSRequest(method=method, url=url)
    SigV4Auth(credentials, "execute-api", ctx.region).add_auth(request)
    req = urllib.request.Request(url, method=method, headers=dict(request.headers))
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _poll_apigw_until(probe, expected_status: int, timeout_s: float = 60.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last[0] == expected_status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"expected status {expected_status}, last={last!r} after {timeout_s}s")


def _get_credentials_with_retry(ctx, identity_id: str, logins=None, timeout_s=45.0, interval_s=3.0):
    cid = ctx.client("cognito-identity")
    kwargs = {"IdentityId": identity_id}
    if logins:
        kwargs["Logins"] = logins
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cid.get_credentials_for_identity(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidIdentityPoolConfigurationException":
                raise
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
