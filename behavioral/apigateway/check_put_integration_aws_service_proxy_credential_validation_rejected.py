"""put-integration-aws-service-proxy-credential-validation-rejected."""
from __future__ import annotations

import json
import time
from typing import Optional

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-integration-aws-service-proxy-credential-validation-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutIntegration validates an AWS-type credentials role server-side, distinct from ARN shape checks."""
    apigw = ctx.client("apigateway")
    iam = ctx.client("iam")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")

    uri = f"arn:aws:apigateway:{ctx.region}:sns:action/ListTopics"

    # 1. Malformed credentials value: rejected by cheap string-shape validation
    # before any attempt to resolve or assume a role.
    code, message = _error(lambda: apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="AWS",
        integrationHttpMethod="GET", uri=uri, credentials="not-an-arn-at-all",
    ))
    assert code == "BadRequestException", f"expected BadRequestException for malformed credentials, got {code!r}"
    assert message == (
        'Invalid ARN specified in the request'
    ), f"unexpected {code} message: {message!r}"
    absent_code, absent_message = _error(lambda: apigw.get_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET"
    ))
    assert absent_code == "NotFoundException", "malformed-credentials PutIntegration must not have created an integration"
    assert absent_message == (
        'Invalid Integration identifier specified'
    ), f"unexpected {absent_code} message: {absent_message!r}"

    # 2. Well-formed IAM role ARN whose trust policy does NOT allow
    # apigateway.amazonaws.com to assume it: PutIntegration accepts it
    # outright (assumability is a data-plane concern, not checked at config
    # time) -- distinct from #1's pure string-shape rejection. The failure
    # only surfaces later, when API Gateway actually tries to assume the role
    # to serve a request.
    untrusted_role = _create_role(ctx, iam, trusted_service="ec2.amazonaws.com")
    _attach_sns_list_topics(ctx, iam, untrusted_role["name"])
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="AWS",
        integrationHttpMethod="GET", uri=uri, credentials=untrusted_role["arn"],
    )
    integration = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert integration["credentials"] == untrusted_role["arn"], (
        "PutIntegration with a well-formed but unassumable role ARN must be accepted server-side"
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    deadline = time.monotonic() + 60
    last_status: Optional[int] = None
    while time.monotonic() < deadline:
        result = apigw.test_invoke_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
        last_status = result["status"]
        if last_status != 200:
            break
        time.sleep(5)
    assert last_status is not None and last_status != 200, (
        f"expected invoking through an unassumable-role integration to fail, got status={last_status}"
    )

    # 3. Positive control: a role apigateway.amazonaws.com CAN assume is
    # accepted and actually serves live traffic end to end.
    trusted_role = _create_role(ctx, iam, trusted_service="apigateway.amazonaws.com")
    _attach_sns_list_topics(ctx, iam, trusted_role["name"])
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="AWS",
        integrationHttpMethod="GET", uri=uri, credentials=trusted_role["arn"],
    )
    # The statusCode-200 method response (owned by the Method) was already
    # created in step 2 and persists across PutIntegration calls. The
    # integration response (owned by the Integration) does not, since
    # PutIntegration replaces the whole integration -- recreate it.
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    integration = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert integration["credentials"] == trusted_role["arn"], (
        f"expected recorded credentials {trusted_role['arn']!r}, got {integration['credentials']!r}"
    )

    deadline = time.monotonic() + 60
    status: Optional[int] = None
    while time.monotonic() < deadline:
        result = apigw.test_invoke_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
        status = result["status"]
        if status == 200:
            break
        time.sleep(5)
    assert status == 200, f"trusted-role integration never invoked successfully (last status={status})"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_role(ctx, iam, trusted_service: str) -> dict:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trusted_service}, "Action": "sts:AssumeRole"}],
    }
    name = ctx.unique_name("sim2real-behav-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return {"name": name, "arn": role_arn}


def _attach_sns_list_topics(ctx, iam, role_name: str) -> None:
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sns:ListTopics", "Resource": "*"}],
    }
    policy_name = "sns-list-topics"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
