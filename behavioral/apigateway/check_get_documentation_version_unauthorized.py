"""get-documentation-version-unauthorized."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-documentation-version-unauthorized"
GROUP = 'error-semantics'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _delete_role(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise

def _restricted_client(ctx, service, max_attempts=12):
    """Create an IAM role trusted by this account's root with an explicit deny-all inline
    policy, assume it, and return (`service` client signing with those temporary credentials,
    the assumed-role ARN) -- so any control-plane call is guaranteed to be rejected for lack of
    permission."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_name = f"{role_name}-deny"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
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
            # IAM role/trust/policy propagation before the role is reliably assumable —
            # bounded retry with a deadline, never an unconditional wait.
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
    assumed_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    return ctx.client(service, creds=cred_kwargs), assumed_arn


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDocumentationVersion on a REAL documentationVersion, called with
    credentials carrying NO apigateway permission, fails with an authorization
    error rather than being conflated with (or fabricated as) NotFoundException.
    """
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    ag.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties=json.dumps({"description": "sim2real-behav"}),
    )
    version_name = ctx.unique_name("v-")
    ag.create_documentation_version(restApiId=api_id, documentationVersion=version_name)

    # Positive control: a properly-authorized caller can fetch this REAL version. Without
    # this, an authorization-failure code below would be indistinguishable from
    # GetDocumentationVersion simply being broken for every caller.
    positive = ag.get_documentation_version(restApiId=api_id, documentationVersion=version_name)
    assert positive["version"] == version_name, (
        f"expected the authorized caller's GetDocumentationVersion to return the real version "
        f"{version_name!r}, got {positive.get('version')!r}"
    )

    restricted, assumed_arn = _restricted_client(ctx, "apigateway")
    unauthorized_code, unauthorized_message = _error(
        lambda: restricted.get_documentation_version(
            restApiId=api_id, documentationVersion=version_name
        )
    )
    assert unauthorized_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with no apigateway permission fetching a "
        f"REAL documentation version, got {unauthorized_code}"
    )
    expected_denial = (
        f"User: {assumed_arn} is not authorized to perform: apigateway:GET on resource: "
        f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/documentation/versions/{version_name} "
        f"with an explicit deny in an identity-based policy"
    )
    assert unauthorized_message == expected_denial, (
        f"unexpected AccessDeniedException message {unauthorized_message!r}"
    )

    not_found_code, not_found_message = _error(
        lambda: ag.get_documentation_version(
            restApiId=api_id, documentationVersion="sim2real-no-such-version"
        )
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent documentationVersion "
        f"(with a properly-authorized caller), got {not_found_code}"
    )
    assert not_found_message == "Invalid Documentation version specified", (
        f"unexpected NotFoundException message {not_found_message!r}"
    )
    assert unauthorized_code != not_found_code, (
        "the no-permission and missing-version failures must be distinct codes"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
