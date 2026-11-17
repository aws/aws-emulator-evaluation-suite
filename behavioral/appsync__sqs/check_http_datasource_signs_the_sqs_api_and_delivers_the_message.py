"""http-datasource-signs-the-sqs-api-and-delivers-the-message."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "http-datasource-signs-the-sqs-api-and-delivers-the-message"
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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AppSync HTTP data source with an IAM-signed SQS endpoint delivers SendMessage's exact
    body to the queue it names, read back through the native ReceiveMessage."""
    appsync = ctx.client("appsync")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    queue_name = ctx.unique_name("sim2real-behav-q-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_arn = _create_role(ctx, iam, "sqs:SendMessage", queue_arn)

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

    payload = ctx.unique_name("sim2real-behav-payload-")
    result = _invoke_until_signed(ctx, graphql_url, api_key, payload, queue_url)
    assert result["statusCode"] == 200, (
        f"SendMessage through the signed HTTP data source returned statusCode "
        f"{result['statusCode']!r}: {result['body']!r}"
    )
    sent_body = json.loads(result["body"])
    assert "MessageId" in sent_body, f"SendMessage response carried no MessageId: {sent_body!r}"

    received = _poll_for_message(sqs, queue_url, timeout_s=30.0)
    assert received is not None, "the queue never received the message sent through AppSync"
    assert received["Body"] == payload, (
        f"ReceiveMessage returned body {received['Body']!r}, expected the payload {payload!r} "
        f"the resolver sent"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])


def _create_role(ctx, iam, action: str, resource_arn: str) -> str:
    """An IAM role AppSync can assume, whose only inline permission is `action` on `resource_arn`."""
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
    iam.put_role_policy(
        RoleName=name,
        PolicyName="sqs-send",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sqs-send"))
    return arn


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


def _invoke_until_signed(ctx, url: str, api_key: str, payload: str, queue_url: str) -> dict:
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
