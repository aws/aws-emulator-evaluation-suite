"""get-method-unauthorized-vs-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-method-unauthorized-vs-not-found"
GROUP = 'error-semantics'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _refusal_once_credentials_settle(fn, attempts=15):
    """_error(fn), retried while fresh assumed-role credentials are still unknown to the
    service (UnrecognizedClientException); the last refusal is returned after ``attempts``."""
    code, message = _error(fn)
    for _ in range(attempts):
        if code != "UnrecognizedClientException":
            break
        time.sleep(2)
        code, message = _error(fn)
    return code, message

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "get-method-unauthorized-vs-not-found"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _put_mock_method(ag, api_id, resource_id, http_method="GET"):
    """A fully integrated MOCK method (deployable without a real backend)."""
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                  authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                       type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                           statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                                statusCode="200", responseTemplates={"application/json": '{"message": "ok"}'})

def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise

def _restricted_client(ctx, service, max_attempts=12):
    """Assume a fresh IAM role with no permissions policy; return (a `service` client using its
    credentials, the assumed-role principal ARN AWS names in a refusal)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-behav-restricted-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "get-method-unauthorized-vs-not-found"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    # The assume_role retry loop bounds IAM role/trust propagation (max_attempts * 2s).
    session_name = ctx.unique_name("sess-")[:64]
    creds = None
    last_exc = None
    for _ in range(max_attempts):
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name
            )["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    if creds is None:
        assert last_exc is not None
        raise last_exc
    cred_kwargs = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    # GetCallerIdentity needs no permission — use it to settle transient InvalidClientTokenId.
    probe = ctx.client("sts", creds=cred_kwargs)
    for _ in range(max_attempts):
        try:
            probe.get_caller_identity()
            break
        except ClientError:
            time.sleep(2)
    principal = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    return ctx.client(service, creds=cred_kwargs), principal


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMethod returns NotFoundException for an undefined method on an existing resource, and
    AccessDeniedException with the no-allow message for a caller with no apigateway permission."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    _put_mock_method(ag, api_id, resource_id, "GET")

    # Positive control: a permitted GetMethod succeeds, so the refusals below are specific.
    positive = ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert positive["httpMethod"] == "GET", (
        f"expected the ordinary GetMethod call to succeed and echo httpMethod=GET, got {positive!r}"
    )

    not_found_code, not_found_message = _error(
        lambda: ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="DELETE")
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for a method never defined on an existing resource, got {not_found_code}"
    )
    assert not_found_message == "Invalid Method identifier specified", (
        f"unexpected NotFoundException message: {not_found_message!r}"
    )

    restricted, principal = _restricted_client(ctx, "apigateway")
    unauthorized_code, unauthorized_message = _refusal_once_credentials_settle(
        lambda: restricted.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    )
    assert unauthorized_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with no apigateway permission, got {unauthorized_code}"
    )
    method_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/resources/{resource_id}/methods/GET"
    expected = (
        f"User: {principal} is not authorized to perform: apigateway:GET on resource: {method_arn} "
        "because no identity-based policy allows the apigateway:GET action"
    )
    assert unauthorized_message == expected, (
        f"expected the no-allow message {expected!r}, got {unauthorized_message!r}"
    )
    assert not_found_code != unauthorized_code, (
        "the missing-method and no-permission failures must be distinct codes"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
