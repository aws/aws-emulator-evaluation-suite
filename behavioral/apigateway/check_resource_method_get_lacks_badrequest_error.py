"""resource-method-get-lacks-badrequest-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

CHECK = "resource-method-get-lacks-badrequest-error"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetMethod/GetMethodResponse/GetResource model no BadRequestException (unlike GetModel);
    missing sub-resources raise NotFoundException, and a deny-all caller reading an existing method
    response gets AccessDeniedException, distinct from NotFoundException."""
    apigw = ctx.client("apigateway")

    for op_name in ("GetMethod", "GetMethodResponse", "GetResource"):
        errs = {s.name for s in apigw.meta.service_model.operation_model(op_name).error_shapes}
        assert errs == {
            "NotFoundException",
            "TooManyRequestsException",
            "UnauthorizedException",
        }, f"unexpected error contract for {op_name}: {errs}"
        assert "BadRequestException" not in errs, (
            f"expected no BadRequestException in the modeled {op_name} error contract, got {errs}"
        )

    model_errs = {s.name for s in apigw.meta.service_model.operation_model("GetModel").error_shapes}
    assert "BadRequestException" in model_errs, (
        f"expected the sibling GetModel operation to model BadRequestException for contrast, got {model_errs}"
    )

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    code, message = _error(lambda: apigw.get_resource(restApiId=api_id, resourceId="nonexistent-resource-id"))
    assert code == "NotFoundException", code
    assert message == "Invalid Resource identifier specified", f"unexpected GetResource message {message!r}"

    code, message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert code == "NotFoundException", code
    assert message == "Invalid Method identifier specified", f"unexpected GetMethod message {message!r}"

    mr_not_found_code, message = _error(
        lambda: apigw.get_method_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
        )
    )
    assert mr_not_found_code == "NotFoundException", mr_not_found_code
    assert message == "Invalid Method identifier specified", f"unexpected GetMethodResponse message {message!r}"

    # Positive control: once the method/method-response actually exist, the same calls succeed.
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert method["httpMethod"] == "GET", f"expected httpMethod GET, got {method.get('httpMethod')}"
    method_response = apigw.get_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert method_response["statusCode"] == "200", (
        f"expected statusCode 200, got {method_response.get('statusCode')}"
    )

    # Change only the caller identity (a deny-all role) against the now-existing method response.
    restricted, assumed_arn = _restricted_client(ctx, "apigateway")
    # Fresh session credentials can briefly read as unknown to API Gateway: retry to a deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while True:
        unauthorized_code, message = _error(
            lambda: restricted.get_method_response(
                restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
            )
        )
        if unauthorized_code != "UnrecognizedClientException" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert unauthorized_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with no apigateway "
        f"permission fetching a REAL method response, got {unauthorized_code}"
    )
    partition = assumed_arn.split(":")[1]
    expected = (
        f"User: {assumed_arn} is not authorized to perform: apigateway:GET on resource: "
        f"arn:{partition}:apigateway:{ctx.region}::/restapis/{api_id}/resources/{root_id}"
        "/methods/GET/responses/200 with an explicit deny in an identity-based policy"
    )
    assert message == expected, f"unexpected {unauthorized_code} message {message!r}"
    assert unauthorized_code != mr_not_found_code, (
        "the no-permission and missing-method-response failures must be distinct codes"
    )

    # The denial is scoped to the restricted session: the original caller still succeeds.
    restored = apigw.get_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert restored["statusCode"] == "200", (
        f"expected the identical call to succeed again with proper permissions, got {restored}"
    )


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _target_client(ctx, service, creds):
    """A `service` client against the same target as ctx.client(service), signing with `creds`."""
    return ctx.client(service, creds=creds)


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
    """Assume a fresh IAM role with an explicit deny-all inline policy; return (a `service` client
    using its credentials, the assumed-role ARN)."""
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
    creds = None
    assumed_arn = None
    last_exc = None
    for _ in range(max_attempts):
        try:
            assumed = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sess-")[:64]
            )
            creds, assumed_arn = assumed["Credentials"], assumed["AssumedRoleUser"]["Arn"]
            break
        except ClientError as exc:
            # IAM role/trust/policy propagation delay before the role is reliably assumable.
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
    # GetCallerIdentity needs no permission -- use it to settle transient InvalidClientTokenId.
    probe = _target_client(ctx, "sts", cred_kwargs)
    for _ in range(max_attempts):
        try:
            probe.get_caller_identity()
            break
        except ClientError:
            time.sleep(2)
    return _target_client(ctx, service, cred_kwargs), assumed_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
