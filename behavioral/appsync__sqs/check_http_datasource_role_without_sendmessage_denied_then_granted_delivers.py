"""http-datasource-role-without-sendmessage-denied-then-granted-delivers."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "http-datasource-role-without-sendmessage-denied-then-granted-delivers"
GROUP = "resource-binding"
SERVICES = ["appsync", "sqs"]

_SCHEMA = """schema {
    query: Query
    mutation: Mutation
}

type Query {
    ping: String
}

type SendResult {
    statusCode: Int!
    body: String!
}

type Mutation {
    sendToQueue(queueUrl: String!, body: String!): SendResult
}
"""

_RESOLVER_CODE = """export function request(ctx) {
  return {
    method: 'POST',
    resourcePath: '/',
    params: {
      headers: {
        'Content-Type': 'application/x-amz-json-1.0',
        'X-Amz-Target': 'AmazonSQS.SendMessage',
      },
      body: JSON.stringify({ QueueUrl: ctx.args.queueUrl, MessageBody: ctx.args.body }),
    },
  };
}

export function response(ctx) {
  if (ctx.error) {
    return { statusCode: 0, body: ctx.error.type + ': ' + ctx.error.message };
  }
  return { statusCode: ctx.result.statusCode, body: ctx.result.body };
}
"""

_MUTATION = (
    "mutation($q: String!, $b: String!) "
    "{ sendToQueue(queueUrl: $q, body: $b) { statusCode body } }"
)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AppSync HTTP data source whose role lacks sqs:SendMessage is refused by SQS itself with
    AccessDenied and delivers nothing; granting the action on the same role makes the identical
    mutation deliver the message."""
    appsync = ctx.client("appsync")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    queue_name = ctx.unique_name("sim2real-behav-q-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_name, role_arn = _create_role_without_policy(ctx, iam)

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"), authenticationType="API_KEY"
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    graphql_url = api.get("uris", {}).get("GRAPHQL")
    assert graphql_url, f"GraphQL API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"

    _create_schema(appsync, api_id, _SCHEMA)
    ds = appsync.create_data_source(
        apiId=api_id,
        name="sim2real_sqs_http",
        type="HTTP",
        serviceRoleArn=role_arn,
        httpConfig={
            "endpoint": ctx.service_url(f"https://sqs.{ctx.region}.amazonaws.com"),
            "authorizationConfig": {
                "authorizationType": "AWS_IAM",
                "awsIamConfig": {"signingRegion": ctx.region, "signingServiceName": "sqs"},
            },
        },
    )["dataSource"]
    appsync.create_resolver(
        apiId=api_id,
        typeName="Mutation",
        fieldName="sendToQueue",
        dataSourceName=ds["name"],
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=_RESOLVER_CODE,
    )
    api_key = appsync.create_api_key(apiId=api_id, description="sim2real-xsvc")["apiKey"]["id"]

    denied_payload = ctx.unique_name("sim2real-behav-denied-")
    denied = _invoke_until_role_assumable(ctx, graphql_url, api_key, denied_payload, queue_url)
    assert denied["statusCode"] == 403, (
        f"SendMessage with no sqs:SendMessage grant returned statusCode {denied['statusCode']!r}, "
        f"expected 403: {denied['body']!r}"
    )
    denied_body = json.loads(denied["body"])
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/APPSYNC_ASSUME_ROLE is not "
        f"authorized to perform: sqs:sendmessage on resource: {queue_arn} because no "
        f"identity-based policy allows the sqs:sendmessage action"
    )
    assert denied_body == {
        "__type": "com.amazon.coral.service#AccessDeniedException",
        "Message": expected_message,
    }, f"expected AccessDeniedException with the exact denial message, got {denied_body!r}"

    absent_after_denial = _poll_for_message(sqs, queue_url, timeout_s=10.0)
    assert absent_after_denial is None, (
        f"a message arrived despite the denied SendMessage: {absent_after_denial!r}"
    )

    _grant_send_message(ctx, iam, role_name, queue_arn)
    granted_payload = ctx.unique_name("sim2real-behav-granted-")
    still_denied_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/APPSYNC_ASSUME_ROLE is not "
        f"authorized to perform: sqs:sendmessage on resource: {queue_arn} because no "
        f"identity-based policy allows the sqs:sendmessage action"
    )
    granted = _invoke_until_policy_effective(
        ctx, graphql_url, api_key, granted_payload, queue_url, still_denied_message
    )
    assert granted["statusCode"] == 200, (
        f"the identical mutation after granting sqs:SendMessage returned statusCode "
        f"{granted['statusCode']!r}: {granted['body']!r}"
    )
    received = _poll_for_message(sqs, queue_url, timeout_s=30.0)
    assert received is not None, "the queue never received the message after the grant"
    assert received["Body"] == granted_payload, (
        f"ReceiveMessage returned body {received['Body']!r}, expected {granted_payload!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])


def _create_role_without_policy(ctx, iam) -> tuple[str, str]:
    """An IAM role AppSync can assume, carrying no inline or managed permission at all."""
    name = ctx.unique_name("sim2real-behav-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "appsync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _grant_send_message(ctx, iam, role_name: str, queue_arn: str) -> None:
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sqs-send",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send"))


def _create_schema(appsync, api_id: str, definition: str) -> None:
    appsync.start_schema_creation(apiId=api_id, definition=definition.encode())
    deadline = time.monotonic() + 90
    status: dict = {}
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)
        if status.get("status") in ("SUCCESS", "FAILED"):
            break
        time.sleep(1.5)
    assert status.get("status") == "SUCCESS", f"schema creation did not succeed: {status!r}"


def _graphql(ctx, url: str, api_key: str, variables: dict) -> dict:
    import requests

    routed_url, route_headers = ctx.endpoint_route(url)
    r = requests.post(
        routed_url,
        json={"query": _MUTATION, "variables": variables},
        headers={"x-api-key": api_key, "Content-Type": "application/json", **route_headers},
        timeout=20,
        verify=ctx.http_verify,
    )
    assert r.status_code == 200, f"GraphQL endpoint returned HTTP {r.status_code}: {r.text[:400]!r}"
    body = r.json()
    assert not body.get("errors"), f"sendToQueue mutation returned GraphQL errors: {body['errors']!r}"
    return body["data"]["sendToQueue"]


def _invoke_until_role_assumable(ctx, url: str, api_key: str, payload: str, queue_url: str) -> dict:
    """Call sendToQueue, retrying only the IAM-propagation window where AppSync cannot yet
    assume the data source role (no API reports when the role becomes usable)."""
    deadline = time.monotonic() + 60.0
    result: dict = {}
    while True:
        result = _graphql(ctx, url, api_key, {"q": queue_url, "b": payload})
        if not _is_role_not_yet_assumable(result) or time.monotonic() >= deadline:
            return result
        time.sleep(2.0)


def _is_role_not_yet_assumable(result: dict) -> bool:
    return result["statusCode"] == 0 and result["body"].startswith("Unauthorized: Unable to assume role")


def _invoke_until_policy_effective(
    ctx, url: str, api_key: str, payload: str, queue_url: str, still_denied_message: str
) -> dict:
    """Call sendToQueue, retrying only the IAM-propagation window where the just-granted
    sqs:SendMessage policy has not yet taken effect (no API reports when a put_role_policy
    grant becomes effective)."""
    deadline = time.monotonic() + 60.0
    result: dict = {}
    while True:
        result = _invoke_until_role_assumable(ctx, url, api_key, payload, queue_url)
        if result["statusCode"] != 403 or time.monotonic() >= deadline:
            return result
        if json.loads(result["body"]) != {
            "__type": "com.amazon.coral.service#AccessDeniedException",
            "Message": still_denied_message,
        }:
            return result
        time.sleep(2.0)


def _poll_for_message(sqs, queue_url: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
