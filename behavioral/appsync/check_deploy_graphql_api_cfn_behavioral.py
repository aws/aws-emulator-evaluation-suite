"""deploy-graphql-api-cfn-behavioral."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-graphql-api-cfn-behavioral"
GROUP = "deploy"
SERVICES = ["appsync"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ApiNameParam:
    Type: String
Resources:
  BehavGraphQLApi:
    Type: AWS::AppSync::GraphQLApi
    Properties:
      Name: !Ref ApiNameParam
      AuthenticationType: API_KEY
  BehavApiKey:
    Type: AWS::AppSync::ApiKey
    Properties:
      ApiId: !GetAtt BehavGraphQLApi.ApiId
  BehavSchema:
    Type: AWS::AppSync::GraphQLSchema
    Properties:
      ApiId: !GetAtt BehavGraphQLApi.ApiId
      Definition: |
        type Query {
          behavHello: String
        }
  BehavNoneDataSource:
    Type: AWS::AppSync::DataSource
    Properties:
      ApiId: !GetAtt BehavGraphQLApi.ApiId
      Name: BehavNoneDS
      Type: NONE
  BehavHelloResolver:
    Type: AWS::AppSync::Resolver
    DependsOn: BehavSchema
    Properties:
      ApiId: !GetAtt BehavGraphQLApi.ApiId
      TypeName: Query
      FieldName: behavHello
      DataSourceName: !GetAtt BehavNoneDataSource.Name
      Kind: UNIT
      RequestMappingTemplate: |
        {
          "version": "2018-05-29",
          "payload": {}
        }
      ResponseMappingTemplate: |
        $util.toJson("sim2real-cfn-templated-response")
Outputs:
  ApiIdOut:
    Value: !GetAtt BehavGraphQLApi.ApiId
  GraphQLUrlOut:
    Value: !GetAtt BehavGraphQLApi.GraphQLUrl
  ApiKeyOut:
    Value: !GetAtt BehavApiKey.ApiKey
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GraphQL API + NONE data source + unit resolver deployed via CloudFormation actually
    answers a query with the templated response after CREATE_COMPLETE."""
    stack_name = ctx.unique_name("sim2real-appsync-cfn-")
    api_name = ctx.unique_name("sim2real_cfn_api_").replace("-", "_")

    outputs = _deploy_cfn(ctx, _TEMPLATE, stack_name, {"ApiNameParam": api_name})

    graphql_url = outputs["GraphQLUrlOut"]
    api_key = outputs["ApiKeyOut"]
    api_id = outputs["ApiIdOut"]

    appsync = ctx.client("appsync")
    api = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert api["name"] == api_name, f"expected api name {api_name!r}, got {api['name']!r}"

    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="behavHello")["resolver"]
    assert resolver["dataSourceName"] == "BehavNoneDS", (
        f"expected resolver bound to BehavNoneDS, got {resolver['dataSourceName']!r}"
    )

    result = _poll_until(
        lambda: _graphql_query(ctx, graphql_url, api_key, "{ behavHello }"),
        lambda r: "data" in r and r["data"].get("behavHello") is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert "errors" not in result, f"unexpected GraphQL errors: {result.get('errors')}"
    assert result["data"]["behavHello"] == "sim2real-cfn-templated-response", result


def _deploy_cfn(ctx, template_body: str, stack_name: str, parameters: dict) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack["StackStatus"]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except Exception:  # noqa: BLE001 - transient propagation errors while polling
            last = None
        else:
            if predicate(last):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _graphql_query(ctx, url: str, api_key: str, query: str) -> dict:
    body = json.dumps({"query": query}).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url,
        data=body,
        method="POST",
        headers={"content-type": "application/json", "x-api-key": api_key, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read().decode("utf-8"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
