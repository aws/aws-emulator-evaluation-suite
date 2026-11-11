"""get-resource-unauthorized."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-unauthorized"
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
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise

def _restricted_client(ctx, service, max_attempts=12):
    """Create an IAM role trusted by this account's root, with no permissions
    policy, assume it, and return (a `service` client signing with those temporary credentials,
    the assumed-role principal ARN AWS names in its refusal) — so any control-plane call is
    guaranteed to be rejected for lack of permission."""
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
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
    """GetResource on a REAL resourceId with credentials that carry NO apigateway
    permission fails with an authorization error, never the same NotFoundException
    a genuinely-missing resourceId would produce.
    """
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]

    authorized = ag.get_resource(restApiId=api_id, resourceId=resource_id)
    assert authorized["id"] == resource_id, (
        f"positive control failed: expected the fully-permissioned caller to read back the "
        f"resource it just created, got {authorized!r}"
    )

    not_found_code, not_found_message = _error(
        lambda: ag.get_resource(restApiId=api_id, resourceId="sim2realNOTFOUND")
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent resourceId, got {not_found_code}"
    )
    assert not_found_message == "Invalid Resource identifier specified", (
        f"unexpected NotFoundException message: {not_found_message!r}"
    )

    restricted, principal = _restricted_client(ctx, "apigateway")
    unauthorized_code, unauthorized_message = _refusal_once_credentials_settle(
        lambda: restricted.get_resource(restApiId=api_id, resourceId=resource_id)
    )
    assert unauthorized_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with no apigateway permission fetching a "
        f"REAL resource, got {unauthorized_code}"
    )
    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/resources/{resource_id}"
    expected = (
        f"User: {principal} is not authorized to perform: apigateway:GET on resource: {resource_arn} "
        "because no identity-based policy allows the apigateway:GET action"
    )
    assert unauthorized_message == expected, (
        f"expected the no-allow message {expected!r}, got {unauthorized_message!r}"
    )
    assert unauthorized_code != not_found_code, (
        "the no-permission and missing-resource failures must be distinct codes"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
