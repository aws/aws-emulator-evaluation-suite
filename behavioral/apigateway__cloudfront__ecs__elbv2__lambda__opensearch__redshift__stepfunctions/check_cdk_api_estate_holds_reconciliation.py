"""cdk-api-estate-holds-reconciliation."""
from __future__ import annotations

import json
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-api-estate-holds-reconciliation"
GROUP = "deploy"
SERVICES = ["apigateway", "apigatewayv2", "athena", "bedrock-agent", "cloudformation",
            "cloudfront", "cloudwatch", "cognito-identity", "cognito-idp", "dynamodb", "ec2",
            "ecr", "ecs", "efs", "elbv2", "iam", "kms", "lambda", "logs", "opensearch",
            "redshift", "redshift-data", "route53", "s3", "s3vectors", "sagemaker",
            "secretsmanager", "sqs", "ssm", "stepfunctions", "sts"]

_APP = "cdk_api_observability_estate"
# --ci keeps the CLI off a TTY; --no-notices / --no-version-reporting keep it off the network.
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")

_BOOTSTRAP_TIMEOUT_S = 1200.0
_DEPLOY_TIMEOUT_S = 5400.0
_DESTROY_TIMEOUT_S = 5400.0
#: The runner's teardown budget for this suite (its redshift member's 1800 s) less a margin.
#: Teardown bounds its own waits by it: ctx.time_left() counts down the run's budget, not the
#: teardown's.
_TEARDOWN_S = 1740.0
#: Teardown time held back from the stack deletes for the steps after them.
_AFTER_STACKS_S = 420.0
_POLL_S = 2.0

#: The logical-id prefix of the role the REST API retains as API Gateway's account CloudWatch role.
_CLOUDWATCH_ROLE_LOGICAL_ID = "ServiceApiCloudWatchRole"

#: The estate's three regions, as its source declares them: the primary, a western and a
#: south-east Asian one. Every client and stack names its region; none follows the runner's.
_REGIONS = {
    "east": "us-east-1",  # region-pinned: the estate's primary region, as its source declares
    "west": "us-west-2",  # region-pinned: the estate's western region, as its source declares
    "apse": "ap-southeast-1",  # region-pinned: the estate's south-east Asian region
}

#: Each stack part and the region key it deploys to.
_PARTS = {
    "AppRoles": "east", "TenantOnlyCdn": "east", "Redshift": "east", "Orchestrator": "east",
    "OpenSearchSlr": "east", "CognitoSearch": "east", "AuditedSearch": "east",
    "StaleTargetsSearch": "east", "KnowledgeBases": "east", "AssistantConfig": "east",
    "QuartzNlb": "east", "MainVpc": "west", "WebSocket": "east", "TigrisService": "east",
    "AgreementsApi": "east", "MotionDetection": "apse", "StreamManager": "east", "Onyx": "east",
    "TeamLogs": "west", "DeploymentStatus": "east", "TenantProvisioning": "east",
    "AnalyticsBuckets": "east", "Reconciliation": "west",
}
#: Stacks others depend on (an import, an ordering), deleted only after every other stack.
_DEPENDED_ON = ("KnowledgeBases", "AnalyticsBuckets", "OpenSearchSlr")

#: The reconciliation function's configured timeout, and the lines it logs once its S3 call
#: returns.
_RECONCILIATION_TIMEOUT_S = 600
_S3_OUTCOMES = ("Successfully stored analytics", "Failed to store analytics",
                "Completed processing")
#: The addresses the stale-target groups hold; nothing in the VPC answers on them.
_STALE_IPS = {"10.80.4.37", "10.80.8.112"}
_NODE_SCRIPTS = {"flint-node.sh", "flint-node-persistent.sh", "flint-node-professional.sh"}
#: The read-only role's AWS managed policies, sorted; it also holds the app's S3 Vectors policy.
_READONLY_POLICIES = ["AmazonS3TablesReadOnlyAccess", "ReadOnlyAccess"]
#: The roles nothing assumes, by name suffix, and the one service each trusts; they hold no policy.
_UNUSED_SERVICE_ROLES = {
    "bedrock-access": "bedrock.amazonaws.com",
    "redshift-copy-unload": "redshift.amazonaws.com",
    "sagemaker-exec": "sagemaker.amazonaws.com",
}
_ALB_LOG_COLUMNS = [
    "type", "time", "elb", "client_ip", "client_port", "target_ip", "target_port",
    "request_processing_time", "target_processing_time", "response_processing_time",
    "elb_status_code", "target_status_code", "received_bytes", "sent_bytes", "request_verb",
    "request_url", "request_proto", "user_agent", "ssl_cipher", "ssl_protocol",
    "target_group_arn", "trace_id", "domain_name", "chosen_cert_arn", "matched_rule_priority",
    "request_creation_time", "actions_executed", "redirect_url", "lambda_error_reason",
    "target_port_list", "target_status_code_list", "classification", "classification_reason",
]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:eventing", "concern:metrics", "concern:negative-classes",
      "dp:api", "dp:native", "plane:control", "plane:data",
      "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A three-region CDK estate deploys whole, serves, and destroys all but the role it retains.

    Nothing is reachable from outside the account; its APIs, workflows, stream processors,
    services, warehouse, vector store and queues serve, and the read-only role's write is refused.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node", "docker")

    account = ctx.client("sts").get_caller_identity()["Account"]
    regions = dict(_REGIONS)
    apigw = ctx.client("apigateway", region=regions["east"])

    qualifier = ctx.unique_name("q")[:10]
    prefix = ctx.unique_name("sim2real-")[:17]
    state: dict[str, Any] = {
        "account": account,
        "regions": regions,
        "prefix": prefix,
        "qualifier": qualifier,
        "toolkit": ctx.unique_name("sim2real-cdktk-"),
        "stacks": {part: (f"{prefix}-{part}", regions[key]) for part, key in _PARTS.items()},
        "resources": {},
        "prior_cloudwatch_role": apigw.get_account().get("cloudwatchRoleArn", ""),
        "cloudwatch_role": None,
    }
    work = _stage_app(ctx, _APP)
    # Registered before anything exists, so a run that fails anywhere still reaps all of it.
    ctx.on_cleanup(lambda: _teardown(ctx, state))

    context = {"account": account, "prefix": prefix, "qualifier": qualifier, **regions}
    for key, region in regions.items():
        context[f"azs_{key}"] = ",".join(_zones(ctx.client("ec2", region=region)))

    _bootstrap(ctx, state)
    try:
        _cdk(ctx, work, ["deploy", "--all", "--require-approval", "never", "--concurrency", "10",
                         "--tags", f"sim2real={CHECK}"], context, timeout_s=_DEPLOY_TIMEOUT_S)
    finally:
        _record_resources(ctx, state)

    # 1. every stack of the estate is CREATE_COMPLETE.
    out: dict[str, dict[str, str]] = {}
    for part, (name, region) in state["stacks"].items():
        stack = ctx.client("cloudformation", region=region).describe_stacks(
            StackName=name)["Stacks"][0]
        assert stack["StackStatus"] == "CREATE_COMPLETE", (
            f"stack {name!r} in {region} is {stack['StackStatus']!r}, expected CREATE_COMPLETE"
        )
        out[part] = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    _assert_agreements_api_serves_and_readonly_write_refused(ctx, state, out["AgreementsApi"])
    _assert_account_cloudwatch_role_is_the_stacks(ctx, state)
    _assert_app_roles(ctx, state)
    _assert_orchestrator_cannot_invoke(ctx, state, out["Orchestrator"])
    _assert_tenant_workflow_provisions(ctx, state, out["TenantProvisioning"])
    _assert_tenant_only_distribution(ctx, state, out["TenantOnlyCdn"])
    _assert_stream_processors(ctx, state, out["Onyx"])
    _assert_websocket_handlers_fail_import(ctx, state, out["WebSocket"], out["StreamManager"])
    _assert_tigris_service_serves(ctx, state, out["TigrisService"])
    _assert_quartz_nlb(ctx, state, out["QuartzNlb"])
    _assert_search_domains(ctx, state, out)
    _assert_dashboards_sign_in(ctx, state, out["CognitoSearch"])
    home_volume = _assert_warehouse_and_domain(ctx, state, out["Redshift"])
    _assert_knowledge_bases(ctx, state, out["KnowledgeBases"], out["AssistantConfig"])
    _assert_reconciliation(ctx, state, out["Reconciliation"], out["AnalyticsBuckets"])
    _assert_team_role_decisions(ctx, state, out["TeamLogs"], out["Reconciliation"])
    _assert_motion_detection(ctx, state, out["MotionDetection"])
    status = ctx.client("ssm", region=regions["east"]).get_parameter(
        Name=out["DeploymentStatus"]["DeploymentStatusParamName"])["Parameter"]["Value"]
    assert status == "pending", f"the deployment-status parameter holds {status!r}"

    # 2. destroy removes every stack and what each owns, except the role it retains. Stacks
    # that wait on VPC network interfaces delete slowly, so independent ones delete together.
    _cdk(ctx, work, ["destroy", "--all", "--force", "--concurrency", "10"], context,
         timeout_s=_DESTROY_TIMEOUT_S)
    for name, region in state["stacks"].values():
        gone = _error(f"DescribeStacks on destroyed stack {name}",
                      lambda name=name, region=region: ctx.client(
                          "cloudformation", region=region).describe_stacks(StackName=name))
        assert gone == ("ValidationError", f"Stack with id {name} does not exist"), (
            f"after `cdk destroy --all`, DescribeStacks on {name!r} returned {gone!r}"
        )
    _assert_owned_resources_gone(ctx, state, out, home_volume)
    retained = state["cloudwatch_role"]
    trust = ctx.client("iam").get_role(RoleName=retained)["Role"]["AssumeRolePolicyDocument"]
    principals = [st.get("Principal", {}).get("Service") for st in trust["Statement"]]
    assert principals == ["apigateway.amazonaws.com"], (
        f"the API Gateway CloudWatch role {retained!r} is created with a Retain policy and must "
        f"outlive `cdk destroy` trusted by API Gateway; its trust principals are {principals!r}"
    )


def _assert_agreements_api_serves_and_readonly_write_refused(ctx, state, out) -> None:
    east = state["regions"]["east"]
    apigw = ctx.client("apigateway", region=east)
    ddb = ctx.client("dynamodb", region=east)
    api_id = out["ApiId"]
    resources = apigw.get_resources(restApiId=api_id, limit=500)["items"]
    by_path = {r.get("path"): r["id"] for r in resources}
    path = "/data-agreements/{agreementId}"
    assert path in by_path, f"REST API {api_id!r} lacks {path}: {sorted(by_path)!r}"
    method = apigw.get_method(restApiId=api_id, resourceId=by_path[path], httpMethod="GET")
    assert method["authorizationType"] == "AWS_IAM", (
        f"GET {path} has authorization {method['authorizationType']!r}, expected AWS_IAM"
    )
    assert apigw.get_stages(restApiId=api_id)["item"] == [], "the REST API has a stage"
    assert apigw.get_deployments(restApiId=api_id)["items"] == [], "the REST API is deployed"

    agreement_id = ctx.unique_name("dua-")
    item = {"agreementId": {"S": agreement_id}, "owner": {"S": "quartz-d3a"},
            "status": {"S": "ACTIVE"}}
    ddb.put_item(TableName=out["TableName"], Item=item)
    # The function reads eventually consistently, so the item may lag its write briefly.
    served = _poll_until(
        ctx, lambda: apigw.test_invoke_method(
            restApiId=api_id, resourceId=by_path[path], httpMethod="GET",
            pathWithQueryString=f"/data-agreements/{agreement_id}"),
        lambda r: r["status"] == 200, timeout_s=60.0,
        description=f"GET /data-agreements/{agreement_id} to return 200")
    assert served["status"] == 200, (
        f"GET /data-agreements/{agreement_id} returned {served['status']!r}; log tail "
        f"{served.get('log', '')[-600:]!r}"
    )
    body = json.loads(served["body"])
    assert body == {"agreementId": agreement_id, "owner": "quartz-d3a", "status": "ACTIVE"}, (
        f"GET /data-agreements/{agreement_id} returned {body!r}, not the stored item"
    )
    missing = apigw.test_invoke_method(restApiId=api_id, resourceId=by_path[path],
                                       httpMethod="GET",
                                       pathWithQueryString="/data-agreements/" +
                                       ctx.unique_name("absent-"))
    assert (missing["status"], json.loads(missing["body"])) == (
        404, {"error": "Agreement not found"}), (
        f"GET of an unknown agreement returned {missing['status']!r} {missing['body']!r}"
    )

    # The read-only application role reads the table and is refused a write to it.
    iam = ctx.client("iam")
    role_arn = iam.get_role(RoleName=f"{state['prefix']}-app-readonly")["Role"]["Arn"]
    assumed = ctx.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="readonly-probe")
    creds = {
        "aws_access_key_id": assumed["Credentials"]["AccessKeyId"],
        "aws_secret_access_key": assumed["Credentials"]["SecretAccessKey"],
        "aws_session_token": assumed["Credentials"]["SessionToken"],
    }
    readonly = ctx.client("dynamodb", region=east, creds=creds)
    table_arn = out["TableArn"]
    refused = _error("PutItem as the read-only role", lambda: readonly.put_item(
        TableName=out["TableName"], Item={"agreementId": {"S": ctx.unique_name("ro-")}}))
    caller = assumed["AssumedRoleUser"]["Arn"]
    assert refused == (
        "AccessDeniedException",
        f"User: {caller} is not authorized to perform: dynamodb:PutItem on resource: "
        f"{table_arn} because no identity-based policy allows the dynamodb:PutItem action",
    ), f"PutItem as the read-only role returned {refused!r}"
    # CONTROL, ordered after the refusal: the same credentials read the stored item.
    got = readonly.get_item(TableName=out["TableName"],
                            Key={"agreementId": {"S": agreement_id}}, ConsistentRead=True)
    assert got.get("Item") == item, f"GetItem as the read-only role returned {got.get('Item')!r}"


def _role_holds(iam, role: str) -> dict:
    statements = iam.get_role(RoleName=role)["Role"]["AssumeRolePolicyDocument"]["Statement"]
    arns = [entry["PolicyArn"]
            for listing in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role)
            for entry in listing["AttachedPolicies"]]
    return {"trust": [statement["Principal"] for statement in statements],
            "aws": sorted(a.rsplit("/", 1)[1] for a in arns if ":iam::aws:policy/" in a),
            "customer": sorted(a.rsplit("/", 1)[1] for a in arns if ":iam::aws:policy/" not in a),
            "inline": len(iam.list_role_policies(RoleName=role)["PolicyNames"])}


def _assert_app_roles(ctx, state) -> None:
    iam = ctx.client("iam")
    prefix = state["prefix"]

    def holds(role: str) -> dict:
        return {k: v for k, v in _role_holds(iam, role).items() if k != "trust"}

    readonly = holds(f"{prefix}-app-readonly")
    want = {"aws": _READONLY_POLICIES, "customer": [f"{prefix}-s3vectors-ro"], "inline": 0}
    assert readonly == want, f"the read-only role holds {readonly!r}, expected {want!r}"

    for suffix, service in _UNUSED_SERVICE_ROLES.items():
        got = _role_holds(iam, f"{prefix}-{suffix}")
        want = {"trust": [{"Service": service}], "aws": [], "customer": [], "inline": 0}
        assert got == want, (
            f"role {prefix}-{suffix} trusts and holds {got!r}, expected to trust only {service} "
            f"and to hold no policy"
        )
    # Its one inline policy reads the session bucket and retrieves from the knowledge bases.
    agent = _role_holds(iam, f"{prefix}-bedrock-exec")
    want = {"trust": [{"Service": "bedrock.amazonaws.com"}], "aws": [], "customer": [],
            "inline": 1}
    assert agent == want, f"the Bedrock agent role trusts and holds {agent!r}, expected {want!r}"

    operator = f"{prefix}-app-admin"
    held = holds(operator)
    assert held == {"aws": ["ReadOnlyAccess"], "customer": [], "inline": 0}, (
        f"role {operator!r} holds {held!r}"
    )
    arn = iam.get_role(RoleName=operator)["Role"]["Arn"]
    results = iam.simulate_principal_policy(
        PolicySourceArn=arn, ActionNames=["iam:CreateUser", "s3:ListAllMyBuckets"])
    decisions = {r["EvalActionName"]: r["EvalDecision"] for r in results["EvaluationResults"]}
    assert decisions == {"iam:CreateUser": "implicitDeny", "s3:ListAllMyBuckets": "allowed"}, (
        f"role {operator!r} evaluates to {decisions!r}"
    )


def _assert_account_cloudwatch_role_is_the_stacks(ctx, state) -> None:
    _find_cloudwatch_role(state)
    ours = state["cloudwatch_role"]
    assert ours, (
        f"the AgreementsApi stack has no {_CLOUDWATCH_ROLE_LOGICAL_ID}* role: "
        f"{state['resources'].get('AgreementsApi', [])!r}"
    )
    arn = ctx.client("apigateway", region=state["regions"]["east"]).get_account().get(
        "cloudwatchRoleArn", "")
    assert arn.rsplit("/", 1)[-1] == ours, (
        f"the account's API Gateway CloudWatch role is {arn!r}, not the stack's role {ours!r}"
    )


def _assert_orchestrator_cannot_invoke(ctx, state, out) -> None:
    sfn = ctx.client("stepfunctions", region=state["regions"]["east"])
    execution_arn = sfn.start_execution(stateMachineArn=out["StateMachineArn"],
                                        input=json.dumps({"jobId": ctx.unique_name("job-")}))[
        "executionArn"]
    execution = _poll_until(ctx, lambda: sfn.describe_execution(executionArn=execution_arn),
                            lambda e: e["status"] != "RUNNING", timeout_s=300.0,
                            description=f"execution {execution_arn} to finish")
    assert (execution["status"], execution.get("error"), execution.get("cause")) == (
        "FAILED", "JobProcessingFailed", "Job processing did not complete successfully"), (
        f"the orchestrator execution ended {execution['status']!r} with "
        f"{execution.get('error')!r}: {execution.get('cause')!r}"
    )
    events = [e for page in sfn.get_paginator("get_execution_history").paginate(
        executionArn=execution_arn) for e in page["events"]]
    failed = [e["taskFailedEventDetails"] for e in events if e["type"] == "TaskFailed"]
    assert len(failed) == 1 and failed[0]["resourceType"] == "lambda", (
        f"the execution recorded TaskFailed events {failed!r}, expected one lambda failure"
    )
    assert "is not authorized to perform: lambda:InvokeFunction" in failed[0].get("cause", ""), (
        f"the lambda task failed for another reason than the role's missing invoke permission: "
        f"{failed[0]!r}"
    )


def _assert_tenant_workflow_provisions(ctx, state, out) -> None:
    east = state["regions"]["east"]
    sfn = ctx.client("stepfunctions", region=east)
    tenant = ctx.unique_name("tenant-")
    execution_arn = sfn.start_execution(stateMachineArn=out["TenantProvisioningWorkflowArn"],
                                        input=json.dumps({"tenant_id": tenant}))["executionArn"]
    execution = _poll_until(ctx, lambda: sfn.describe_execution(executionArn=execution_arn),
                            lambda e: e["status"] != "RUNNING", timeout_s=420.0,
                            description=f"execution {execution_arn} to finish")
    assert execution["status"] == "SUCCEEDED", (
        f"the provisioning execution ended {execution['status']!r}: {execution.get('error')!r} "
        f"{execution.get('cause')!r}"
    )
    assert json.loads(execution["output"]) == {"tenant_id": tenant,
                                               "provisioning_complete": True}, execution["output"]
    record = ctx.client("dynamodb", region=east).get_item(
        TableName=out["TenantsTableName"], Key={"tenant_id": {"S": tenant}},
        ConsistentRead=True).get("Item", {})
    summary = {k: record.get(k) for k in ("status", "file_count", "tenant_url")}
    assert summary == {
        "status": {"S": "PROVISIONED"}, "file_count": {"N": "2"},
        "tenant_url": {"S": f"https://{out['DistributionDomainName']}/{tenant}/"},
    }, f"the tenant record after provisioning is {record!r}"
    s3 = ctx.client("s3", region=east)
    page = s3.get_object(Bucket=out["TenantServicesBucketName"], Key=f"{tenant}/index.html")
    assert f"<h1>Welcome to {tenant}</h1>" in page["Body"].read().decode(), (
        f"{tenant}/index.html does not carry the tenant's heading"
    )
    script = s3.head_object(Bucket=out["TenantServicesBucketName"], Key=f"{tenant}/app.js")
    assert script["ContentType"] == "application/javascript", script["ContentType"]
    config = ctx.client("cloudfront").get_distribution_config(Id=out["DistributionId"])
    assert config["DistributionConfig"]["Enabled"] is False, (
        f"the tenant content distribution is enabled: {config['DistributionConfig']['Enabled']!r}"
    )


def _assert_tenant_only_distribution(ctx, state, out) -> None:
    cloudfront = ctx.client("cloudfront")
    config = cloudfront.get_distribution_config(Id=out["DistributionId"])["DistributionConfig"]
    assert config.get("ConnectionMode") == "tenant-only", config.get("ConnectionMode")
    group = cloudfront.get_connection_group(Identifier=out["ConnectionGroupId"])
    assert group["ConnectionGroup"]["Enabled"] is True, group["ConnectionGroup"]
    policy = json.loads(ctx.client("s3", region=state["regions"]["east"]).get_bucket_policy(
        Bucket=out["TenantServicesBucketName"])["Policy"])
    sids = [st.get("Sid") for st in policy["Statement"]]
    assert sids == ["DenyNonSSL"], (
        f"the tenant services bucket policy holds statements {sids!r}; it grants the "
        f"distribution nothing"
    )
    zone = ctx.client("route53").get_hosted_zone(Id=out["HostedZoneId"])["HostedZone"]
    assert zone["Name"] == f"{state['prefix']}-tenant.net.", zone["Name"]


def _assert_stream_processors(ctx, state, out) -> None:
    east = state["regions"]["east"]
    lam = ctx.client("lambda", region=east)
    ddb = ctx.client("dynamodb", region=east)
    logs = ctx.client("logs", region=east)
    for function in (out["OnyxFunctionName"], out["OnyxBetaFunctionName"]):
        _poll_until(ctx, lambda function=function: [
            m["State"] for m in lam.list_event_source_mappings(
                FunctionName=function)["EventSourceMappings"]],
            lambda states: bool(states) and all(s == "Enabled" for s in states),
            timeout_s=300.0, description=f"{function}'s event source mappings to be enabled")

    table = out["BasaltRequestsTableName"]
    request_id = ctx.unique_name("req-")
    ddb.put_item(TableName=table, Item={"id": {"S": request_id}, "state": {"S": "PENDING"}})
    ddb.update_item(TableName=table, Key={"id": {"S": request_id}},
                    UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":s": {"S": "IN_PROGRESS"}})
    _wait_log_line(ctx, logs, out["OnyxLogGroup"], request_id,
                   f"Processing request {request_id} from table {table}: state changed from "
                   f"PENDING to IN_PROGRESS")

    beta_id = ctx.unique_name("req-")
    ddb.put_item(TableName=out["BasaltRequestsBetaTableName"],
                 Item={"id": {"S": beta_id}, "state": {"S": "IN_PROGRESS"}})
    _wait_log_line(ctx, logs, f"/aws/lambda/{out['OnyxBetaFunctionName']}", beta_id,
                   f"Processing request {beta_id} in IN_PROGRESS state (event: INSERT)")


def _assert_websocket_handlers_fail_import(ctx, state, websocket, stream_manager) -> None:
    east = state["regions"]["east"]
    lam = ctx.client("lambda", region=east)
    apigwv2 = ctx.client("apigatewayv2", region=east)
    for out in (websocket, stream_manager):
        api_id = out["WebSocketApiId"]
        routes = {r["RouteKey"] for r in apigwv2.get_routes(ApiId=api_id)["Items"]}
        assert routes == {"$connect", "$disconnect", "$default"}, (
            f"WebSocket API {api_id!r} has routes {sorted(routes)!r}"
        )
        assert apigwv2.get_stages(ApiId=api_id)["Items"] == [], f"API {api_id!r} has a stage"
        event = {"requestContext": {"connectionId": ctx.unique_name("conn-"),
                                    "routeKey": "$connect"}}
        result = lam.invoke(FunctionName=out["LambdaFunctionName"],
                            Payload=json.dumps(event).encode())
        payload = json.loads(result["Payload"].read())
        assert result.get("FunctionError") == "Unhandled", (
            f"{out['LambdaFunctionName']} answered $connect with {payload!r}; its runtime has no "
            f"'aws-sdk' module, so loading the handler fails"
        )
        message = payload.get("errorMessage", "")
        assert payload.get("errorType") == "Runtime.ImportModuleError", payload
        assert message.startswith(
            "Error: Cannot find module 'aws-sdk'\nRequire stack:\n- /var/task/message.js\n"
        ) and message.endswith("/var/runtime/index.mjs"), payload
    deployments = apigwv2.get_deployments(ApiId=stream_manager["WebSocketApiId"])["Items"]
    assert [d["DeploymentId"] for d in deployments] == [stream_manager["DeploymentId"]], (
        f"the stream manager API has deployments {deployments!r}"
    )
    keys = {o["Key"] for o in ctx.client("s3", region=east).list_objects_v2(
        Bucket=stream_manager["NodeScriptsBucketName"]).get("Contents", [])}
    assert keys == _NODE_SCRIPTS, f"the node scripts bucket holds {sorted(keys)!r}"


def _assert_tigris_service_serves(ctx, state, out) -> None:
    east = state["regions"]["east"]
    elbv2 = ctx.client("elbv2", region=east)
    scheme = elbv2.describe_load_balancers(LoadBalancerArns=[out["ALBArn"]])[
        "LoadBalancers"][0]["Scheme"]
    assert scheme == "internal", f"the tigris load balancer has scheme {scheme!r}"
    health = _poll_until(
        ctx, lambda: elbv2.describe_target_health(
            TargetGroupArn=out["TargetGroupArn"])["TargetHealthDescriptions"],
        lambda ts: len(ts) == 1 and ts[0]["TargetHealth"]["State"] == "healthy",
        timeout_s=600.0, description="the tigris API task to be a healthy target")
    assert [t["TargetHealth"]["State"] for t in health] == ["healthy"], health
    _wait_log_line(ctx, ctx.client("logs", region=east), out["ClientLogGroupName"],
                   "updateStatus", "POST /jobInstance/updateStatus -> 200", timeout_s=420.0)

    athena = ctx.client("athena", region=east)
    database = out["GlueDatabaseName"]
    query_id = athena.start_query_execution(
        QueryString=f'SELECT * FROM "{database}"."{out["GlueTableName"]}" LIMIT 1',
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": f"s3://{out['AthenaResultsBucketName']}/results/"},
    )["QueryExecutionId"]
    execution = _poll_until(
        ctx, lambda: athena.get_query_execution(QueryExecutionId=query_id)["QueryExecution"],
        lambda e: e["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=180.0, description=f"query {query_id} to finish")
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]
    columns = [c["Name"] for c in athena.get_query_results(QueryExecutionId=query_id)[
        "ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
    assert columns == _ALB_LOG_COLUMNS, f"the ALB log table reads columns {columns!r}"


def _assert_quartz_nlb(ctx, state, out) -> None:
    east = state["regions"]["east"]
    elbv2 = ctx.client("elbv2", region=east)
    nlb = elbv2.describe_load_balancers(LoadBalancerArns=[out["NetworkLoadBalancerArn"]])[
        "LoadBalancers"][0]
    assert (nlb["Type"], nlb["Scheme"]) == ("network", "internal"), (nlb["Type"], nlb["Scheme"])
    listeners = elbv2.describe_listeners(LoadBalancerArn=out["NetworkLoadBalancerArn"])[
        "Listeners"]
    forwards = [(lst["Port"], lst["Protocol"], a.get("TargetGroupArn"))
                for lst in listeners for a in lst["DefaultActions"]]
    assert forwards == [(9090, "TCP", out["MgmtTargetGroupArn"])], forwards
    group = ctx.client("ec2", region=east).describe_security_groups(
        GroupIds=[out["SecurityGroupId"]])["SecurityGroups"][0]
    ingress = sorted((p["FromPort"], r["CidrIp"]) for p in group["IpPermissions"]
                     for r in p.get("IpRanges", []))
    assert ingress == [(8080, out["VpcCidr"]), (9090, out["VpcCidr"])], ingress


def _assert_search_domains(ctx, state, out) -> None:
    east = state["regions"]["east"]
    opensearch = ctx.client("opensearch", region=east)
    names = {
        "cognito": out["CognitoSearch"]["OpenSearchDomainName"],
        "audited": out["AuditedSearch"]["OpenSearchDomainName"],
        "stale": out["StaleTargetsSearch"]["DomainName"],
    }
    domains = _poll_until(
        ctx, lambda: {d["DomainName"]: d for d in opensearch.describe_domains(
            DomainNames=list(names.values()))["DomainStatusList"]},
        lambda ds: len(ds) == 3 and not any(d["Processing"] for d in ds.values()),
        timeout_s=900.0, description="the three domains to finish processing")
    for name in names.values():
        domain = domains[name]
        assert not domain["Processing"], f"domain {name!r} is still processing"
        assert "vpc" in domain.get("Endpoints", {}) and "Endpoint" not in domain, (
            f"domain {name!r} has endpoints {domain.get('Endpoints')!r} / "
            f"{domain.get('Endpoint')!r}; every domain is private to its VPC"
        )
    assert domains[names["cognito"]]["CognitoOptions"]["Enabled"] is True
    for label in ("audited", "stale"):
        assert domains[names[label]]["AdvancedSecurityOptions"]["Enabled"] is True, label
    audit = domains[names["audited"]]["LogPublishingOptions"].get("AUDIT_LOGS", {})
    expected = out["AuditedSearch"]["AuditLogGroupArn"].removesuffix(":*")
    assert audit.get("Enabled") is True and audit.get(
        "CloudWatchLogsLogGroupArn", "").removesuffix(":*") == expected, (
        f"the audited domain publishes audit logs as {audit!r}, expected to {expected!r}"
    )

    elbv2 = ctx.client("elbv2", region=east)
    health = _poll_until(
        ctx, lambda: elbv2.describe_target_health(
            TargetGroupArn=out["StaleTargetsSearch"]["DashboardsTgArn"])[
            "TargetHealthDescriptions"],
        lambda ts: len(ts) == 2 and all(t["TargetHealth"]["State"] == "unhealthy" for t in ts),
        timeout_s=600.0, description="the stale dashboards targets to be judged unhealthy")
    seen = {(t["Target"]["Id"], t["Target"]["Port"], t["TargetHealth"]["State"]) for t in health}
    assert seen == {(ip, 443, "unhealthy") for ip in _STALE_IPS}, (
        f"the dashboards target group reports {seen!r}; its addresses answer nothing"
    )


def _assert_dashboards_sign_in(ctx, state, out) -> None:
    east = state["regions"]["east"]
    idp = ctx.client("cognito-idp", region=east)
    pool, client = out["UserPoolId"], out["UserPoolClientId"]
    name = ctx.unique_name("user-")
    # Generated per run and only ever sent as a password field, which the runner redacts.
    password = "Aa1!" + secrets.token_urlsafe(18)
    state["cognito_user"] = {"pool": pool, "name": name}
    idp.admin_create_user(UserPoolId=pool, Username=name, MessageAction="SUPPRESS",
                          UserAttributes=[{"Name": "email", "Value": f"{name}@example.com"},
                                          {"Name": "email_verified", "Value": "true"}])
    idp.admin_set_user_password(UserPoolId=pool, Username=name, Password=password,
                                Permanent=True)

    def sign_in(secret: str) -> dict:
        return idp.admin_initiate_auth(UserPoolId=pool, ClientId=client,
                                       AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                                       AuthParameters={"USERNAME": name, "PASSWORD": secret})

    refused = _error("ADMIN_USER_PASSWORD_AUTH with a wrong password",
                     lambda: sign_in(password + "x"))
    assert refused == ("NotAuthorizedException", "Incorrect username or password."), (
        f"a wrong password was answered with {refused!r}"
    )
    # CONTROL, ordered after the refusal: the right password signs the same user in.
    signed_in = sign_in(password)
    assert "ChallengeName" not in signed_in, (
        f"sign-in returned challenge {signed_in.get('ChallengeName')!r} for a permanent password"
    )
    tokens = signed_in["AuthenticationResult"]
    shape = {
        "tokens": sorted(k for k in ("IdToken", "AccessToken", "RefreshToken") if tokens.get(k)),
        "TokenType": tokens.get("TokenType"),
        "ExpiresIn": tokens.get("ExpiresIn"),
    }
    assert shape == {"tokens": ["AccessToken", "IdToken", "RefreshToken"],
                     "TokenType": "Bearer", "ExpiresIn": 3600}, (
        f"the sign-in token set has the shape {shape!r}"
    )

    identity = ctx.client("cognito-identity", region=east)
    logins = {f"cognito-idp.{east}.amazonaws.com/{pool}": tokens["IdToken"]}
    identity_id = identity.get_id(IdentityPoolId=out["IdentityPoolId"], Logins=logins)[
        "IdentityId"]
    assert identity_id.startswith(f"{east}:"), f"GetId returned identity {identity_id!r}"
    issued = identity.get_credentials_for_identity(IdentityId=identity_id, Logins=logins)
    credentials = issued["Credentials"]
    present = sorted(k for k in ("AccessKeyId", "SecretKey", "SessionToken", "Expiration")
                     if credentials.get(k))
    assert issued["IdentityId"] == identity_id and present == [
        "AccessKeyId", "Expiration", "SecretKey", "SessionToken"], (
        f"GetCredentialsForIdentity issued fields {present!r} for {issued['IdentityId']!r}"
    )
    caller = ctx.client("sts", region=east, creds={
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretKey"],
        "aws_session_token": credentials["SessionToken"],
    }).get_caller_identity()["Arn"]
    role_arn = out["AuthenticatedRoleArn"]
    role = role_arn.rsplit("/", 1)[-1]
    expected = f"arn:{role_arn.split(':')[1]}:sts::{state['account']}:assumed-role/{role}/"
    assert caller.startswith(expected), (
        f"the identity's credentials sign as {caller!r}, not the authenticated role {role!r}"
    )
    _delete_sign_in_user(ctx, state)
    gone = _error("AdminGetUser on the deleted user",
                  lambda: idp.admin_get_user(UserPoolId=pool, Username=name))
    assert gone == ("UserNotFoundException", "User does not exist."), (
        f"AdminGetUser on the deleted user returned {gone!r}"
    )


def _assert_warehouse_and_domain(ctx, state, out) -> str:
    east = state["regions"]["east"]
    redshift = ctx.client("redshift", region=east)
    cluster = _poll_until(
        ctx, lambda: redshift.describe_clusters(
            ClusterIdentifier=out["RedshiftClusterIdentifier"])["Clusters"][0],
        lambda c: c["ClusterStatus"] == "available", timeout_s=900.0,
        description="the Redshift cluster to be available")
    assert cluster["ClusterStatus"] == "available", cluster["ClusterStatus"]
    assert (cluster["Encrypted"], cluster["PubliclyAccessible"]) == (True, False), (
        cluster["Encrypted"], cluster["PubliclyAccessible"])
    attached = {g["VpcSecurityGroupId"] for g in cluster["VpcSecurityGroups"]}
    expected = {out[k] for k in ("SgAllowProdCorpId", "SgProdRangesId", "SgDefaultId",
                                 "SgVpcEndpointId")}
    assert attached == expected, (
        f"the cluster carries groups {sorted(attached)!r}, expected {sorted(expected)!r} without "
        f"the internal group {out['SgRedshiftSagemakerId']!r} that admits its port"
    )
    data = ctx.client("redshift-data", region=east)
    statement_id = data.execute_statement(ClusterIdentifier=out["RedshiftClusterIdentifier"],
                                          Database="flintforecast", DbUser="flintadmin",
                                          Sql="SELECT 1 AS one")["Id"]
    statement = _poll_until(ctx, lambda: data.describe_statement(Id=statement_id),
                            lambda s: s["Status"] in ("FINISHED", "FAILED", "ABORTED"),
                            timeout_s=300.0, description=f"statement {statement_id} to finish")
    assert statement["Status"] == "FINISHED", (statement["Status"], statement.get("Error"))
    records = data.get_statement_result(Id=statement_id)["Records"]
    assert records == [[{"longValue": 1}]], f"SELECT 1 returned {records!r}"

    sagemaker = ctx.client("sagemaker", region=east)
    domain = _poll_until(ctx, lambda: sagemaker.describe_domain(
        DomainId=out["SagemakerDomainId"]), lambda d: d["Status"] == "InService",
        timeout_s=600.0, description="the SageMaker domain to be in service")
    settings = {k: domain.get(k) for k in ("Status", "AppNetworkAccessType", "VpcId")}
    assert settings == {"Status": "InService", "AppNetworkAccessType": "VpcOnly",
                        "VpcId": out["VpcId"]}, f"the SageMaker domain reads {settings!r}"
    volume = domain["HomeEfsFileSystemId"]
    efs = ctx.client("efs", region=east)
    fs = efs.describe_file_systems(FileSystemId=volume)["FileSystems"][0]
    owner = {t["Key"]: t["Value"] for t in fs.get("Tags", [])}.get(
        "ManagedByAmazonSageMakerResource")
    assert owner == out["SagemakerDomainArn"], (
        f"home volume {volume!r} is tagged as managed by {owner!r}, not the domain"
    )
    vpcs = {t["VpcId"] for t in efs.describe_mount_targets(FileSystemId=volume)["MountTargets"]}
    assert vpcs == {out["VpcId"]}, f"home volume {volume!r} mounts into VPCs {vpcs!r}"
    return volume


def _assert_knowledge_bases(ctx, state, kb, config) -> None:
    east = state["regions"]["east"]
    agent = ctx.client("bedrock-agent", region=east)
    ids = (kb["MetadataKBKnowledgeBaseId"], kb["EscalationWriteupsKBKnowledgeBaseId"])
    for kb_id, index in zip(ids, ("metadata-index", "escalation-index"), strict=True):
        base = _poll_until(ctx, lambda kb_id=kb_id: agent.get_knowledge_base(
            knowledgeBaseId=kb_id)["knowledgeBase"], lambda b: b["status"] != "CREATING",
            timeout_s=300.0, description=f"knowledge base {kb_id} to be created")
        storage = base["storageConfiguration"]
        vector_store = storage.get("s3VectorsConfiguration", {})
        named = vector_store.get("indexName") or vector_store.get("indexArn", "").rsplit("/", 1)[-1]
        assert (base["status"], storage["type"], named) == ("ACTIVE", "S3_VECTORS", index), (
            base["status"], storage)
    param = ctx.client("ssm", region=east).get_parameter(Name=config["ConfigParamName"])
    referenced = [b["knowledgeBaseId"] for b in json.loads(
        param["Parameter"]["Value"])["knowledgeBases"]]
    assert referenced == list(ids), f"the configuration names knowledge bases {referenced!r}"
    seed = ctx.client("s3", region=east).get_object(Bucket=kb["MetadataDataBucketName"],
                                                    Key="metadata.txt")["Body"].read().decode()
    assert seed.startswith("Flint metadata knowledge base:"), f"the seed document is {seed!r}"

    vectors = ctx.client("s3vectors", region=east)
    key = ctx.unique_name("probe-")
    data = [((i % 7) + 1) / 7.0 for i in range(1024)]
    vectors.put_vectors(vectorBucketName=kb["MetadataVectorBucketName"],
                        indexName="metadata-index",
                        vectors=[{"key": key, "data": {"float32": data}}])
    found = _poll_until(
        ctx, lambda: vectors.query_vectors(
            vectorBucketName=kb["MetadataVectorBucketName"], indexName="metadata-index",
            queryVector={"float32": data}, topK=1, returnDistance=True)["vectors"],
        lambda vs: bool(vs) and vs[0]["key"] == key, timeout_s=60.0,
        description=f"vector {key} to be queryable")
    assert found and found[0]["key"] == key and found[0]["distance"] < 1e-3, (
        f"querying the index with vector {key!r} returned {found!r}"
    )


def _assert_reconciliation(ctx, state, out, buckets) -> None:
    west = state["regions"]["west"]
    sqs = ctx.client("sqs", region=west)
    logs = ctx.client("logs", region=west)
    awslambda = ctx.client("lambda", region=west)
    request_id = ctx.unique_name("rec-")
    sqs.send_message(QueueUrl=out["InputQueueUrl"],
                     MessageBody=json.dumps({"request_id": request_id}))
    _wait_log_line(ctx, logs, out["LogGroupName"], request_id,
                   f"Attempting to store analytics for request: {request_id}", timeout_s=300.0)
    stream = _stream_with(logs, out["LogGroupName"], f"Processing reconciliation request: "
                                                     f"{request_id}")
    finished = [e["message"].strip()
                for page in logs.get_paginator("filter_log_events").paginate(
                    logGroupName=out["LogGroupName"], logStreamNames=[stream])
                for e in page["events"] if any(m in e["message"] for m in _S3_OUTCOMES)]
    assert finished == [], f"the invocation for {request_id!r} logged {finished!r}"
    answers = []
    for message in sqs.receive_message(QueueUrl=out["OutputQueueUrl"], WaitTimeSeconds=5,
                                       MaxNumberOfMessages=10).get("Messages", []):
        if json.loads(message["Body"]).get("request_id") == request_id:
            answers.append(message["Body"])
    assert answers == [], f"the output queue answered {request_id!r} with {answers!r}"
    stored = [o["Key"] for page in ctx.client("s3", region=state["regions"]["east"]).get_paginator(
        "list_objects_v2").paginate(Bucket=buckets["AnalyticsBucketName"], Prefix="analytics/")
        for o in page.get("Contents", []) if o["Key"].endswith(f"/{request_id}.json")]
    assert stored == [], f"the analytics bucket holds {stored!r} for request {request_id!r}"

    # The period that bounds the pending write, as Lambda and SQS report it.
    config = awslambda.get_function_configuration(FunctionName=out["LambdaFunctionName"])
    assert config["Timeout"] == _RECONCILIATION_TIMEOUT_S, (
        f"the reconciliation function reports Timeout {config['Timeout']!r}, configured "
        f"{_RECONCILIATION_TIMEOUT_S} s"
    )
    queue = sqs.get_queue_attributes(QueueUrl=out["InputQueueUrl"],
                                     AttributeNames=["VisibilityTimeout", "QueueArn"])["Attributes"]
    assert queue["VisibilityTimeout"] == str(_RECONCILIATION_TIMEOUT_S), (
        f"the input queue reports VisibilityTimeout {queue['VisibilityTimeout']!r}, configured "
        f"{_RECONCILIATION_TIMEOUT_S} s"
    )
    mappings = [(m["EventSourceArn"], m["BatchSize"])
                for m in awslambda.list_event_source_mappings(
                    FunctionName=out["LambdaFunctionName"])["EventSourceMappings"]]
    assert mappings == [(queue["QueueArn"], 1)], (
        f"the reconciliation function's event-source mappings read {mappings!r}"
    )
    # Redelivery would start the same hung invocation again until the queue's redrive limit.
    sqs.purge_queue(QueueUrl=out["InputQueueUrl"])

    result = awslambda.invoke(FunctionName=out["ConfigLoaderFunctionName"], Payload=b"{}")
    payload = json.loads(result["Payload"].read())
    assert "FunctionError" not in result and payload["statusCode"] == 200, payload
    assert json.loads(payload["body"])["message"] == "Configuration loaded successfully", payload


def _assert_team_role_decisions(ctx, state, team, reconciliation) -> None:
    west = state["regions"]["west"]
    role_arn = team["QuartzTeamRoleArn"]
    partition = role_arn.split(":")[1]
    group = f"arn:{partition}:logs:{west}:{state['account']}:log-group:"
    document = ctx.client("iam").get_role_policy(
        RoleName=role_arn.rsplit("/", 1)[1], PolicyName="CloudWatchLogsReadPolicy")[
        "PolicyDocument"]

    def listed(value) -> list[str]:
        return sorted([value] if isinstance(value, str) else value)

    statements = sorted(((st["Effect"], listed(st["Action"]), listed(st["Resource"]))
                         for st in document["Statement"]), key=repr)
    vended = f"{group}/aws/vendedlogs/bedrock-agentcore/runtime"
    want = sorted([
        ("Allow", ["logs:DescribeLogGroups", "logs:FilterLogEvents", "logs:GetLogEvents"],
         sorted([f"{group}/aws/bedrock-agentcore/*", f"{group}/aws/lambda/*",
                 f"{group}/aws/batch/*"])),
        ("Deny", ["logs:FilterLogEvents", "logs:GetLogEvents"],
         [f"{vended}/APPLICATION_LOGS/*", f"{vended}/USAGE_LOGS/*"]),
    ], key=repr)
    assert statements == want, f"the team role's logs policy reads {statements!r}"
    assert reconciliation["LogGroupName"].startswith("/aws/lambda/"), reconciliation
    assert team["BasaltMcpApplicationLogsGroupName"].startswith(
        "/aws/vendedlogs/bedrock-agentcore/runtime/APPLICATION_LOGS/"), team


def _assert_motion_detection(ctx, state, out) -> None:
    apse = state["regions"]["apse"]
    ecs = ctx.client("ecs", region=apse)
    service = _poll_until(
        ctx, lambda: ecs.describe_services(cluster=out["ClusterName"],
                                           services=[out["ServiceName"]])["services"][0],
        lambda s: s["runningCount"] == 1, timeout_s=600.0,
        description="the motion detection task to run")
    assert (service["runningCount"], service["desiredCount"]) == (1, 1), service["runningCount"]
    lines = _wait_log_line(ctx, ctx.client("logs", region=apse), out["TaskLogGroupName"],
                           "quartz_api_call", "quartz_api_call: operation=ReportPerson latency=",
                           timeout_s=420.0)
    latencies = [float(m.group(1)) for line in lines
                 for m in [re.search(r"latency=([0-9.]+)ms status=200", line)] if m]
    assert latencies and all(2000.0 <= v <= 4500.0 for v in latencies), (
        f"the service logged Quartz latencies {latencies!r}; the healthy mode stays in "
        f"2000-4500 ms"
    )
    cloudwatch = ctx.client("cloudwatch", region=apse)

    def datapoints():
        end = time.time()
        return cloudwatch.get_metric_statistics(
            Namespace="Flint/Dependencies", MetricName="APILatency",
            Dimensions=[{"Name": "Service", "Value": "Quartz"},
                        {"Name": "Operation", "Value": "ReportPerson"}],
            StartTime=end - 1800, EndTime=end + 60, Period=60,
            Statistics=["Average"])["Datapoints"]

    points = _poll_until(ctx, datapoints, bool, timeout_s=300.0,
                         description="the Quartz latency metric to have datapoints")
    assert points and all(2000.0 <= p["Average"] <= 4500.0 for p in points), (
        f"the Quartz latency metric reads {points!r}"
    )

    result = ctx.client("lambda", region=apse).invoke(
        FunctionName=out["QuartzBackfillFunctionName"],
        Payload=json.dumps({"isPulling": "True",
                            "queueName": out["QuartzBackfillDlqName"]}).encode())
    payload = json.loads(result["Payload"].read())
    assert "FunctionError" not in result and payload["statusCode"] == 200, payload
    body = json.loads(payload["body"])
    assert (body["message"], body["messagesProcessed"]) == ("DLQ check completed", 0), body


def _assert_owned_resources_gone(ctx, state, out, home_volume: str) -> None:
    east, west, apse = (state["regions"][k] for k in ("east", "west", "apse"))
    probes = [
        ("agreements table", lambda: ctx.client("dynamodb", region=east).describe_table(
            TableName=out["AgreementsApi"]["TableName"]), ("ResourceNotFoundException",)),
        ("tenant content bucket", lambda: ctx.client("s3", region=east).head_bucket(
            Bucket=out["TenantProvisioning"]["TenantServicesBucketName"]), ("404",)),
        ("audited domain", lambda: ctx.client("opensearch", region=east).describe_domain(
            DomainName=out["AuditedSearch"]["OpenSearchDomainName"]),
         ("ResourceNotFoundException",)),
        ("Redshift cluster", lambda: ctx.client("redshift", region=east).describe_clusters(
            ClusterIdentifier=out["Redshift"]["RedshiftClusterIdentifier"]),
         ("ClusterNotFound",)),
        ("SageMaker domain", lambda: ctx.client("sagemaker", region=east).describe_domain(
            DomainId=out["Redshift"]["SagemakerDomainId"]), ("ResourceNotFound",)),
        ("domain home volume", lambda: ctx.client("efs", region=east).describe_file_systems(
            FileSystemId=home_volume), ("FileSystemNotFound",)),
        ("metadata knowledge base", lambda: ctx.client(
            "bedrock-agent", region=east).get_knowledge_base(
            knowledgeBaseId=out["KnowledgeBases"]["MetadataKBKnowledgeBaseId"]),
         ("ResourceNotFoundException",)),
        ("reconciliation function", lambda: ctx.client("lambda", region=west).get_function(
            FunctionName=out["Reconciliation"]["LambdaFunctionName"]),
         ("ResourceNotFoundException",)),
        ("backfill function", lambda: ctx.client("lambda", region=apse).get_function(
            FunctionName=out["MotionDetection"]["QuartzBackfillFunctionName"]),
         ("ResourceNotFoundException",)),
    ]
    for label, probe, codes in probes:
        code, _ = _error(f"{label} probe", probe)
        assert code in codes, f"after destroy, the {label} answered {code!r}, expected {codes!r}"
    keys = ((east, out["Redshift"]["RedshiftKmsKeyArn"]),
            (west, out["Reconciliation"]["WestKmsKeyArn"]),
            (east, out["AnalyticsBuckets"]["KmsKeyArn"]))
    lifecycle = {arn: ctx.client("kms", region=region).describe_key(KeyId=arn)["KeyMetadata"][
        "KeyState"] for region, arn in keys}
    assert lifecycle == {arn: "PendingDeletion" for _, arn in keys}, (
        f"after destroy, the stacks' keys are {lifecycle!r}; a deleted key waits out its window"
    )


def _zones(ec2) -> list[str]:
    zones = ec2.describe_availability_zones()["AvailabilityZones"]
    return sorted(
        z["ZoneName"]
        for z in zones
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
        and z.get("OptInStatus", "opt-in-not-required") == "opt-in-not-required"
    )


def _physical_ids(state, part: str, resource_type: str, logical_prefix: str = "") -> list[str]:
    return [pid for rtype, pid, lid in state["resources"].get(part, [])
            if rtype == resource_type and lid.startswith(logical_prefix)]


def _record_resources(ctx, state) -> None:
    ids = state.setdefault("stack_ids", {})
    for part, (name, region) in state["stacks"].items():
        cfn = ctx.client("cloudformation", region=region)
        try:
            if part not in ids:
                ids[part] = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
            found = [
                (r["ResourceType"], r["PhysicalResourceId"], r["LogicalResourceId"])
                for page in cfn.get_paginator("list_stack_resources").paginate(
                    StackName=ids[part])
                for r in page["StackResourceSummaries"]
                if r.get("PhysicalResourceId")
            ]
        except ClientError as exc:
            if _stack_missing(exc):
                continue
            raise
        known = state["resources"].setdefault(part, [])
        known.extend(pair for pair in found if pair not in known)


def _wait_log_line(ctx, logs, log_group: str, term: str, needle: str, *,
                   timeout_s: float = 300.0) -> list[str]:
    def matching():
        return [line for line in _log_lines(logs, log_group, term) if needle in line]

    lines = _poll_until(ctx, matching, bool, timeout_s=timeout_s,
                        description=f"{needle!r} in {log_group}")
    assert lines, f"no line in {log_group!r} contains {needle!r}"
    return lines


def _stream_with(logs, log_group: str, needle: str) -> str:
    for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=log_group, filterPattern=f'"{needle}"'):
        for event in page["events"]:
            return event["logStreamName"]
    raise AssertionError(f"no stream of {log_group!r} logs {needle!r}")


def _log_lines(logs, log_group: str, term: str) -> list[str]:
    try:
        return [
            e["message"]
            for page in logs.get_paginator("filter_log_events").paginate(
                logGroupName=log_group, filterPattern=f'"{term}"')
            for e in page["events"]
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _raise_if_budget_spent(ctx, what: str) -> None:
    if _budget_spent(ctx):
        raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")


def _poll_until(ctx, probe, predicate, *, timeout_s: float, description: str):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(_POLL_S)
        last = probe()
    if not predicate(last):
        _raise_if_budget_spent(ctx, description)
    return last


def _error(label: str, fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"the {label} call succeeded but was expected to be refused")


def _stack_missing(exc: ClientError) -> bool:
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _stage_app(ctx, name: str) -> Path:
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present={(source / 'app.py').is_file()}, "
        f"cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _bootstrap(ctx, state) -> None:
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-api-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap",
        *(f"aws://{state['account']}/{region}" for region in state["regions"].values()),
        "--qualifier", state["qualifier"],
        "--toolkit-stack-name", state["toolkit"],
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        # The staging bucket's name does not carry the sim2real prefix, so tag it via the stack.
        "--tags", f"sim2real={CHECK}",
        *_CDK_FLAGS,
    ]
    _run_cli(ctx, command, scratch, _BOOTSTRAP_TIMEOUT_S,
             f"`cdk bootstrap` for qualifier {state['qualifier']!r}")


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *,
         timeout_s: float) -> None:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, *_CDK_FLAGS, "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    _run_cli(ctx, cmd, work, timeout_s, f"`cdk {' '.join(args[:2])}`")


def _run_cli(ctx, cmd: list[str], cwd: Path, timeout_s: float, what: str) -> None:
    try:
        result = subprocess.run(cmd, cwd=cwd, env=ctx.subprocess_env(), capture_output=True,
                                text=True, timeout=_budget_s(ctx, timeout_s))
    except subprocess.TimeoutExpired:
        _raise_if_budget_spent(ctx, what)
        raise
    assert result.returncode == 0, (
        f"{what} exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1500:]!r}"
    )


def _delete_stacks_and_wait(ctx, stacks: list[tuple[str, str]], timeout_s: float,
                            before_retry=None) -> None:
    deadline = time.monotonic() + timeout_s
    failed = _delete_and_settle(ctx, stacks, timeout_s)
    if failed and before_retry is not None:
        for name, _ in failed:
            before_retry(name)
        failed = _delete_and_settle(ctx, failed, max(1.0, deadline - time.monotonic()))
    if failed:
        reasons = {name: _delete_failures(ctx, name, region) for name, region in failed}
        raise AssertionError(f"stacks were not deleted during teardown: {reasons!r}")


def _delete_failures(ctx, stack: str, region: str) -> list[str]:
    try:
        events = ctx.client("cloudformation", region=region).describe_stack_events(
            StackName=stack)["StackEvents"]
    except ClientError as exc:
        return [f"events unreadable: {exc.response['Error'].get('Message', '')}"]
    seen: dict[str, str] = {}
    for event in events:
        if event["ResourceStatus"] == "DELETE_FAILED" and event["LogicalResourceId"] != stack:
            seen.setdefault(event["LogicalResourceId"], event.get("ResourceStatusReason", ""))
    return [f"{lid}: {reason}" for lid, reason in seen.items()]


def _delete_and_settle(ctx, stacks: list[tuple[str, str]], timeout_s: float):
    pending = []
    for name, region in stacks:
        try:
            ctx.client("cloudformation", region=region).delete_stack(StackName=name)
            pending.append((name, region))
        except ClientError as exc:
            if not _stack_missing(exc):
                raise
    failed: list[tuple[str, str]] = []
    deadline = time.monotonic() + timeout_s
    while pending and time.monotonic() <= deadline:
        for name, region in list(pending):
            try:
                status = ctx.client("cloudformation", region=region).describe_stacks(
                    StackName=name)["Stacks"][0]["StackStatus"]
            except ClientError as exc:
                if not _stack_missing(exc):
                    raise
                status = "DELETE_COMPLETE"
            if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
                pending.remove((name, region))
                if status == "DELETE_FAILED":
                    failed.append((name, region))
        if pending:
            time.sleep(_POLL_S)
    return failed + pending


def _empty_and_delete_bucket(ctx, bucket: str, region: str, *, delete: bool = True) -> None:
    s3 = ctx.client("s3", region=region)
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        if delete:
            s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _reap_log_group(logs, name: str, *, reads: int = 3, budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name!r} still present after {budget_s}s")
            time.sleep(_POLL_S)


def _delete_secret(ctx, arn: str, region: str) -> None:
    try:
        ctx.client("secretsmanager", region=region).delete_secret(
            SecretId=arn, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _find_cloudwatch_role(state) -> None:
    roles = _physical_ids(state, "AgreementsApi", "AWS::IAM::Role", _CLOUDWATCH_ROLE_LOGICAL_ID)
    assert len(roles) <= 1, f"more than one {_CLOUDWATCH_ROLE_LOGICAL_ID}* role: {roles!r}"
    if roles:
        state["cloudwatch_role"] = roles[0]


def _restore_cloudwatch_role(ctx, state) -> None:
    apigw = ctx.client("apigateway", region=state["regions"]["east"])
    prior = state["prior_cloudwatch_role"]
    apigw.update_account(patchOperations=[
        {"op": "replace", "path": "/cloudwatchRoleArn", "value": prior}])
    current = apigw.get_account().get("cloudwatchRoleArn", "")
    assert current == prior, (
        f"API Gateway's account CloudWatch role is {current!r} after restoring {prior!r}"
    )


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
            for policy in page["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=name, PolicyArn=policy["PolicyArn"])
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=name):
            for policy in page["PolicyNames"]:
                iam.delete_role_policy(RoleName=name, PolicyName=policy)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _container_repository(state, region: str) -> str:
    return f"cdk-{state['qualifier']}-container-assets-{state['account']}-{region}"


def _empty_repository(ctx, state, region: str) -> None:
    ecr = ctx.client("ecr", region=region)
    name = _container_repository(state, region)
    try:
        for page in ecr.get_paginator("list_images").paginate(repositoryName=name):
            if page["imageIds"]:
                ecr.batch_delete_image(repositoryName=name, imageIds=page["imageIds"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _bootstrap_remnants(ctx, state) -> list[str]:
    qualifier, account = state["qualifier"], state["account"]
    remaining: list[str] = []
    for region in state["regions"].values():
        try:
            status = ctx.client("cloudformation", region=region).describe_stacks(
                StackName=state["toolkit"])["Stacks"][0]["StackStatus"]
            if status != "DELETE_COMPLETE":
                remaining.append(f"toolkit stack {state['toolkit']} in {region} in {status}")
        except ClientError as exc:
            if not _stack_missing(exc):
                raise
        staging = f"cdk-{qualifier}-assets-{account}-{region}"
        try:
            ctx.client("s3", region=region).head_bucket(Bucket=staging)
            remaining.append(f"staging bucket {staging}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
                raise
        try:
            ctx.client("ssm", region=region).get_parameter(
                Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append(f"bootstrap version parameter in {region}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
        repository = _container_repository(state, region)
        try:
            ctx.client("ecr", region=region).describe_repositories(repositoryNames=[repository])
            remaining.append(f"container assets repository {repository}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise
    iam = ctx.client("iam")
    roles = [role["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for role in page["Roles"] if role["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _delete_task_definition(ctx, arn: str, region: str) -> None:
    failures = ctx.client("ecs", region=region).delete_task_definitions(
        taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise AssertionError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _each(items, fn) -> None:
    failures: list[str] = []
    for item in items:
        try:
            fn(item)
        except Exception as exc:  # noqa: BLE001 — collected and raised below, never swallowed
            failures.append(f"{item}: {exc!r}")
    if failures:
        raise AssertionError("; ".join(failures))


def _delete_sign_in_user(ctx, state) -> None:
    user = state.get("cognito_user")
    if not user:
        return
    try:
        ctx.client("cognito-idp", region=state["regions"]["east"]).admin_delete_user(
            UserPoolId=user["pool"], Username=user["name"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("UserNotFoundException",
                                                 "ResourceNotFoundException"):
            raise


def _teardown(ctx, state) -> None:
    end = time.monotonic() + _TEARDOWN_S

    def left(reserve: float = 0.0) -> float:
        return max(1.0, end - reserve - time.monotonic())

    stacks = state["stacks"]
    parts = {name: part for part, (name, _) in stacks.items()}
    deleted: dict[str, bool] = {}

    def empty_buckets(name: str) -> None:
        # A bucket refilled after its auto-delete handler ran fails the stack's delete.
        part = parts[name]
        _each(_physical_ids(state, part, "AWS::S3::Bucket"),
              lambda bucket: _empty_and_delete_bucket(ctx, bucket, stacks[part][1],
                                                      delete=False))

    def wave(label: str, group: list[tuple[str, str]]) -> None:
        _delete_stacks_and_wait(ctx, group, left(_AFTER_STACKS_S), empty_buckets)
        deleted[label] = True

    def retained_role() -> None:
        _find_cloudwatch_role(state)
        if state["cloudwatch_role"]:
            _delete_role(ctx, state["cloudwatch_role"])

    def leftovers() -> None:
        # Deleting a stack only deregisters its task definitions; INACTIVE revisions stay listed.
        items = [("secret", arn, region) for part, (_, region) in stacks.items()
                 for arn in _physical_ids(state, part, "AWS::SecretsManager::Secret")]
        items += [("task definition", arn, region) for part, (_, region) in stacks.items()
                  for arn in _physical_ids(state, part, "AWS::ECS::TaskDefinition")]
        _each(items, lambda item: (_delete_secret if item[0] == "secret"
                                   else _delete_task_definition)(ctx, item[1], item[2]))

    def log_groups() -> None:
        names = [(f"/aws/lambda/{fn}", region) for part, (_, region) in stacks.items()
                 for fn in _physical_ids(state, part, "AWS::Lambda::Function")]
        names += [(f"/aws/ecs/containerinsights/{cluster}/performance", region)
                  for part, (_, region) in stacks.items()
                  for cluster in _physical_ids(state, part, "AWS::ECS::Cluster")]
        # Never below the time its three absent reads take, so a gone group is not residue.
        _each(names, lambda item: _reap_log_group(
            ctx.client("logs", region=item[1]), item[0],
            budget_s=max(10.0, min(180.0, left(120.0)))))

    def bootstrap() -> None:
        if not (deleted.get("first") and deleted.get("last")):
            # A leftover app stack still needs the toolkit's cfn-exec role to be deleted later.
            raise AssertionError(f"staging buckets and toolkit stacks {state['toolkit']} kept: "
                                 f"an app stack was not deleted")
        regions = list(state["regions"].values())
        _each(regions, lambda region: _empty_and_delete_bucket(
            ctx, f"cdk-{state['qualifier']}-assets-{state['account']}-{region}", region))
        _each(regions, lambda region: _empty_repository(ctx, state, region))
        _delete_stacks_and_wait(ctx, [(state["toolkit"], r) for r in regions],
                                min(900.0, left()))

    def remnants() -> None:
        remaining = _bootstrap_remnants(ctx, state)
        if remaining:
            raise AssertionError(f"bootstrap remnants still present: {remaining!r}")

    first = [stacks[p] for p in stacks if p not in _DEPENDED_ON]
    last = [stacks[p] for p in _DEPENDED_ON]
    steps = [
        ("stack resource inventory", lambda: _record_resources(ctx, state)),
        ("API Gateway account CloudWatch role lookup", lambda: _find_cloudwatch_role(state)),
        # The cheap account-wide setting first, so a teardown cut short by its deadline did it.
        ("API Gateway account CloudWatch role setting",
         lambda: _restore_cloudwatch_role(ctx, state)),
        ("sign-in user", lambda: _delete_sign_in_user(ctx, state)),
        (f"app stacks {[n for n, _ in first]}", lambda: wave("first", first)),
        (f"app stacks {[n for n, _ in last]}", lambda: wave("last", last)),
        # A stack a timed-out deploy kept creating may hold resources the first inventory missed.
        ("stack resource inventory after delete", lambda: _record_resources(ctx, state)),
        # Again once the stacks are gone, so a stack a timed-out deploy kept creating cannot have
        # set it after the first restore.
        ("API Gateway account CloudWatch role setting after the stacks",
         lambda: _restore_cloudwatch_role(ctx, state)),
        ("retained API Gateway CloudWatch role", retained_role),
        ("secrets and task definitions", leftovers),
        ("log groups", log_groups),
        (f"bootstrap {state['toolkit']}", bootstrap),
        ("bootstrap remnant probe", remnants),
    ]
    errors: list[str] = []
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — collected and raised below, never swallowed
            errors.append(f"{label}: {exc!r}")
    if errors:
        # Latest first: a report that keeps only the message's tail keeps the earliest failure,
        # the one the later steps' residue follows from.
        raise AssertionError("teardown left residue: " + "; ".join(reversed(errors)))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
