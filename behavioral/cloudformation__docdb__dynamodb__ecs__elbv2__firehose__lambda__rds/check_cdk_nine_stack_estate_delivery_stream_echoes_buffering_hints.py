"""cdk-nine-stack-estate-delivery-stream-echoes-buffering-hints."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-nine-stack-estate-delivery-stream-echoes-buffering-hints"
GROUP = "deploy"
SERVICES = ["apigateway", "athena", "cloudformation", "cloudwatch", "docdb", "dynamodb", "ec2",
            "ecs", "elbv2", "firehose", "iam", "lambda", "logs", "rds", "s3", "secretsmanager",
            "sns"]

_APP = "cdk_workload_estate"
_REGION = "us-east-1"  # region-pinned: the estate is the us-east-1 deployment it reproduces
# --ci keeps the CLI off a TTY; --no-notices / --no-version-reporting keep it off the network.
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 4200.0
_DESTROY_TIMEOUT_S = 3600.0
#: The runner's teardown budget for this suite (its rds member's 1800 s) less a margin. Teardown
#: bounds its own waits by it: ctx.time_left() counts down the run's budget, not the teardown's.
_TEARDOWN_S = 1740.0
#: Teardown time held back from the stack deletes for the steps after them.
_AFTER_STACKS_S = 420.0
_POLL_S = 2.0

#: The logical-id prefix of the role the REST API retains as API Gateway's account CloudWatch role.
_CLOUDWATCH_ROLE_LOGICAL_ID = "ConnectedApiCloudWatchRole"

#: The stack parts, in the app's order; Networking is the one every VPC consumer imports from.
_PARTS = ("AccessRoles", "Networking", "S3Storage", "Monitoring", "Database", "LambdaMisc", "ECS",
          "ComputeEC2", "DocDBAthenaNLB")
_VPC_CONSUMERS = ("Database", "LambdaMisc", "ECS", "ComputeEC2", "DocDBAthenaNLB")
#: The operator role's managed policies: read-only access, never write or administrator access.
_OPERATOR_POLICIES = ["ReadOnlyAccess"]
#: The read-only role's AWS managed policies, sorted; it also holds the app's S3 Vectors policy.
_READONLY_POLICIES = ["AmazonS3TablesReadOnlyAccess", "ReadOnlyAccess"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control",
      "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A nine-stack CDK estate deploys whole, serves, and destroys all but the role it retains.

    Nothing is outside-reachable; its functions, topic, table, database, workgroup and ALB service
    serve, its delivery stream holds its declared buffering, and a role that cannot invoke is refused.

    Reference: https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts", region=_REGION).get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation", region=_REGION)
    apigw = ctx.client("apigateway", region=_REGION)

    qualifier = ctx.unique_name("q")[:10]
    prefix = ctx.unique_name("sim2real-est-")
    state: dict[str, Any] = {
        "account": account,
        "qualifier": qualifier,
        "toolkit": ctx.unique_name("sim2real-cdktk-"),
        "staging": f"cdk-{qualifier}-assets-{account}-{_REGION}",
        "stacks": {part: f"{prefix}-{part}" for part in _PARTS},
        "resources": {},
        "prior_cloudwatch_role": apigw.get_account().get("cloudwatchRoleArn", ""),
        "cloudwatch_role": None,
    }
    work = _stage_app(ctx, _APP)
    # Registered before anything exists, so a run that fails anywhere still reaps all of it.
    ctx.on_cleanup(lambda: _teardown(ctx, state))

    context = {
        "account": account, "region": _REGION, "prefix": prefix, "qualifier": qualifier,
        "azs": ",".join(_zones(ctx.client("ec2", region=_REGION))),
    }
    stacks = state["stacks"]

    _bootstrap(ctx, state)
    try:
        _cdk(ctx, work, ["deploy", "--all", "--require-approval", "never", "--concurrency", "5",
                         "--tags", f"sim2real={CHECK}"], context, timeout_s=_DEPLOY_TIMEOUT_S)
    finally:
        _record_resources(ctx, state)

    # 1. every stack of the estate is CREATE_COMPLETE.
    outputs: dict[str, dict[str, str]] = {}
    for part, name in stacks.items():
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
        assert stack["StackStatus"] == "CREATE_COMPLETE", (
            f"stack {name!r} is {stack['StackStatus']!r}, expected CREATE_COMPLETE"
        )
        outputs[part] = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    _assert_app_roles(ctx, outputs["AccessRoles"])
    _assert_vpc_consumers_import_networking(ctx, state, outputs)
    _assert_api_refused_and_function_serves(ctx, state, outputs["LambdaMisc"])
    _assert_alias_runs_published_version(ctx, outputs["LambdaMisc"])
    _assert_account_cloudwatch_role_is_the_stacks(ctx, state)
    _assert_table_and_database(ctx, state, outputs["Database"])
    _assert_delivery_stream_buffers_into_bucket(ctx, outputs["Monitoring"])
    _assert_workgroup_writes_results(ctx, outputs["DocDBAthenaNLB"])
    _assert_service_behind_alb(ctx, outputs["ECS"])

    # 2. destroy removes every stack and what each owns, except the role it retains.
    _cdk(ctx, work, ["destroy", "--all", "--force"], context, timeout_s=_DESTROY_TIMEOUT_S)
    for name in stacks.values():
        gone = _error(f"DescribeStacks on destroyed stack {name}",
                      lambda name=name: cfn.describe_stacks(StackName=name))
        assert gone == ("ValidationError", f"Stack with id {name} does not exist"), (
            f"after `cdk destroy --all`, DescribeStacks on {name!r} returned {gone!r}"
        )
    _assert_owned_resources_gone(ctx, outputs)
    retained = state["cloudwatch_role"]
    trust = ctx.client("iam", region=_REGION).get_role(
        RoleName=retained)["Role"]["AssumeRolePolicyDocument"]
    principals = [st.get("Principal", {}).get("Service") for st in trust["Statement"]]
    assert principals == ["apigateway.amazonaws.com"], (
        f"the API Gateway CloudWatch role {retained!r} is created with a Retain policy and must "
        f"outlive `cdk destroy` trusted by API Gateway; its trust principals are {principals!r}"
    )


def _role_holds(iam, role: str) -> dict:
    """`role`'s trust principals, AWS and customer managed policy names, and inline count."""
    statements = iam.get_role(RoleName=role)["Role"]["AssumeRolePolicyDocument"]["Statement"]
    arns = [entry["PolicyArn"]
            for listing in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role)
            for entry in listing["AttachedPolicies"]]
    return {"trust": [statement["Principal"] for statement in statements],
            "aws": sorted(a.rsplit("/", 1)[1] for a in arns if ":iam::aws:policy/" in a),
            "customer": sorted(a.rsplit("/", 1)[1] for a in arns if ":iam::aws:policy/" not in a),
            "inline": len(iam.list_role_policies(RoleName=role)["PolicyNames"])}


def _assert_app_roles(ctx, out) -> None:
    """The app roles read only: the operator may not create users, Bedrock's role holds nothing."""
    iam = ctx.client("iam", region=_REGION)

    def holds(role: str) -> dict:
        """`_role_holds` without the trust principals."""
        return {k: v for k, v in _role_holds(iam, role).items() if k != "trust"}

    readonly = holds(out["ReadOnlyRoleName"])
    want = {"aws": _READONLY_POLICIES, "customer": [out["VectorsPolicyName"]], "inline": 0}
    assert readonly == want, f"the read-only role holds {readonly!r}, expected {want!r}"
    bedrock = _role_holds(iam, out["BedrockRoleName"])
    assert bedrock == _service_role_holding_nothing("bedrock.amazonaws.com"), (
        f"the Bedrock role trusts and holds {bedrock!r}, expected to trust only "
        f"bedrock.amazonaws.com and to hold no policy"
    )

    operator = out["AdminRoleName"]
    held = holds(operator)
    assert held == {"aws": _OPERATOR_POLICIES, "customer": [], "inline": 0}, (
        f"role {operator!r} holds {held!r}"
    )
    arn = iam.get_role(RoleName=operator)["Role"]["Arn"]
    results = iam.simulate_principal_policy(
        PolicySourceArn=arn, ActionNames=["iam:CreateUser", "s3:ListAllMyBuckets"])
    decisions = {r["EvalActionName"]: r["EvalDecision"] for r in results["EvaluationResults"]}
    assert decisions == {"iam:CreateUser": "implicitDeny", "s3:ListAllMyBuckets": "allowed"}, (
        f"role {operator!r} evaluates to {decisions!r}"
    )


def _service_role_holding_nothing(service: str) -> dict:
    """What `_role_holds` reads for a role that trusts only `service` and holds no policy."""
    return {"trust": [{"Service": service}], "aws": [], "customer": [], "inline": 0}


def _assert_vpc_consumers_import_networking(ctx, state, outputs) -> None:
    """Each VPC consumer imports Networking's exports, and the instance sits in its VPC."""
    cfn = ctx.client("cloudformation", region=_REGION)
    stacks = state["stacks"]
    networking_id = cfn.describe_stacks(StackName=stacks["Networking"])["Stacks"][0]["StackId"]
    exports = [
        e["Name"]
        for page in cfn.get_paginator("list_exports").paginate()
        for e in page["Exports"]
        if e["ExportingStackId"] == networking_id
    ]
    vpc_export = f"{stacks['Networking']}-VpcId"
    assert vpc_export in exports, f"Networking does not export {vpc_export!r}: {exports!r}"
    importers: set[str] = set()
    for name in exports:
        try:
            for page in cfn.get_paginator("list_imports").paginate(ExportName=name):
                importers.update(page["Imports"])
        except ClientError as exc:
            if exc.response["Error"]["Message"] != f"Export '{name}' is not imported by any stack.":
                raise
    expected = {stacks[part] for part in _VPC_CONSUMERS}
    assert importers == expected, (
        f"the stacks importing Networking's exports are {sorted(importers)!r}, expected exactly "
        f"the VPC consumers {sorted(expected)!r}"
    )
    vpc_id = outputs["Networking"]["VpcId"]
    instance_id = outputs["ComputeEC2"]["EC2InstanceId"]
    instance = ctx.client("ec2", region=_REGION).describe_instances(
        InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert instance["VpcId"] == vpc_id, (
        f"instance {instance_id!r} is in {instance['VpcId']!r}, expected Networking's VPC "
        f"{vpc_id!r}"
    )
    assert instance["MetadataOptions"]["HttpTokens"] == "required", (
        f"instance {instance_id!r} has HttpTokens "
        f"{instance['MetadataOptions']['HttpTokens']!r}; its launch template requires IMDSv2"
    )
    instance_tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    assert instance_tags.get("CreatedBy") == "example-user", (
        f"instance {instance_id!r} carries CreatedBy={instance_tags.get('CreatedBy')!r}, expected "
        f"'example-user'"
    )


def _assert_api_refused_and_function_serves(ctx, state, out) -> None:
    """POST /process cannot invoke the function; a direct invoke and the topic both reach it."""
    lam = ctx.client("lambda", region=_REGION)
    logs = ctx.client("logs", region=_REGION)
    sns = ctx.client("sns", region=_REGION)
    apigw = ctx.client("apigateway", region=_REGION)
    function = out["ConnectedLambdaName"]
    log_group = lam.get_function_configuration(FunctionName=function)["LoggingConfig"]["LogGroup"]

    api_id = _physical_ids(state, "LambdaMisc", "AWS::ApiGateway::RestApi")[0]
    resources = apigw.get_resources(restApiId=api_id, limit=500)["items"]
    by_path = {r.get("path"): r["id"] for r in resources}
    assert {"/process", "/served"} <= set(by_path), (
        f"REST API {api_id!r} lacks /process or /served: {resources!r}"
    )
    refused_marker = ctx.unique_name("refused-")
    refused = apigw.test_invoke_method(restApiId=api_id, resourceId=by_path["/process"],
                                       httpMethod="POST",
                                       body=json.dumps({"marker": refused_marker}))
    assert refused["status"] == 500, (
        f"POST /process through a role without lambda:InvokeFunction returned status "
        f"{refused['status']!r}, expected 500"
    )
    assert "Invalid permissions on Lambda function" in refused.get("log", ""), (
        f"the refused POST /process log does not name the missing Lambda permission: "
        f"{refused.get('log', '')[-600:]!r}"
    )

    # CONTROL, ordered after the refusal: the same integration through a role that may invoke
    # the function answers 200, and the function logs its request.
    served_marker = ctx.unique_name("served-")
    served = apigw.test_invoke_method(restApiId=api_id, resourceId=by_path["/served"],
                                      httpMethod="POST",
                                      body=json.dumps({"marker": served_marker}))
    assert served["status"] == 200, (
        f"POST /served through a role with lambda:InvokeFunction returned status "
        f"{served['status']!r}, expected 200; log tail {served.get('log', '')[-600:]!r}"
    )
    _wait_log_line(ctx, logs, log_group, served_marker)
    assert not _log_lines(logs, log_group, refused_marker), (
        f"log group {log_group!r} holds the refused request's marker {refused_marker!r}: the "
        f"function ran although its API role may not invoke it"
    )

    topic_arn = _physical_ids(state, "LambdaMisc", "AWS::SNS::Topic")[0]
    subscriptions = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    lambda_subs = [s["SubscriptionArn"] for s in subscriptions if s["Protocol"] == "lambda"]
    assert len(lambda_subs) == 1, f"topic {topic_arn!r} has subscriptions {subscriptions!r}"
    sns.publish(TopicArn=topic_arn, Message=ctx.unique_name("published-"))
    _wait_log_line(ctx, logs, log_group, lambda_subs[0])


def _assert_alias_runs_published_version(ctx, out) -> None:
    """Invoking the prod alias executes the published version it points at."""
    lam = ctx.client("lambda", region=_REGION)
    function = out["ConcurrentLambdaName"]
    alias = lam.get_alias(FunctionName=function, Name="prod")
    assert alias["FunctionVersion"] != "$LATEST", f"alias prod points at {alias!r}"
    result = lam.invoke(FunctionName=function, Qualifier="prod", Payload=b"{}")
    assert result["StatusCode"] == 200 and "FunctionError" not in result, (
        f"Invoke of {function}:prod returned {result['StatusCode']!r} "
        f"FunctionError={result.get('FunctionError')!r}"
    )
    assert result["ExecutedVersion"] == alias["FunctionVersion"], (
        f"{function}:prod executed version {result['ExecutedVersion']!r}, expected the alias's "
        f"{alias['FunctionVersion']!r}"
    )
    body = result["Payload"].read()
    assert body == b"null", f"the handler returns undefined; Invoke returned payload {body!r}"


def _assert_account_cloudwatch_role_is_the_stacks(ctx, state) -> None:
    """The REST API's account resource points API Gateway's CloudWatch role at the stack's role."""
    _find_cloudwatch_role(state)
    ours = state["cloudwatch_role"]
    assert ours, (
        f"the LambdaMisc stack has no {_CLOUDWATCH_ROLE_LOGICAL_ID}* role: "
        f"{state['resources'].get('LambdaMisc', [])!r}"
    )
    arn = ctx.client("apigateway", region=_REGION).get_account().get("cloudwatchRoleArn", "")
    assert arn.rsplit("/", 1)[-1] == ours, (
        f"the account's API Gateway CloudWatch role is {arn!r}, not the stack's role {ours!r}"
    )


def _assert_table_and_database(ctx, state, out) -> None:
    """The table persists an item; the instance and its attached secret agree with the outputs."""
    ddb = ctx.client("dynamodb", region=_REGION)
    table = out["EventLogsTableName"]
    item_id = ctx.unique_name("evt-")
    ddb.put_item(TableName=table, Item={"id": {"S": item_id}, "kind": {"S": "deploy"}})
    got = ddb.get_item(TableName=table, Key={"id": {"S": item_id}}, ConsistentRead=True)
    assert got.get("Item") == {"id": {"S": item_id}, "kind": {"S": "deploy"}}, (
        f"GetItem on {table!r} returned {got.get('Item')!r} for the item just written"
    )

    rds = ctx.client("rds", region=_REGION)
    instance = _poll_until(
        ctx, lambda: rds.describe_db_instances(
            DBInstanceIdentifier=out["RdsInstanceId"])["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=900.0, description=f"database instance {out['RdsInstanceId']} to be available")
    assert instance["DBInstanceStatus"] == "available", (
        f"database instance {out['RdsInstanceId']!r} is {instance['DBInstanceStatus']!r}, "
        f"expected available"
    )
    assert instance["AllocatedStorage"] == int(out["RdsEndpointAllocatedStorage"]) == 20, (
        f"the instance has {instance['AllocatedStorage']!r} GiB, the output says "
        f"{out['RdsEndpointAllocatedStorage']!r}, the app asks for 20"
    )
    assert instance["Endpoint"]["Address"] == out["RdsEndpoint"], (
        f"the instance endpoint {instance['Endpoint']['Address']!r} differs from the output "
        f"{out['RdsEndpoint']!r}"
    )
    secret_arn = _physical_ids(state, "Database", "AWS::SecretsManager::Secret")[0]
    secret = json.loads(ctx.client("secretsmanager", region=_REGION).get_secret_value(
        SecretId=secret_arn)["SecretString"])
    attached = {k: secret.get(k) for k in ("engine", "host", "port", "username")}
    assert attached == {"engine": "mysql", "host": out["RdsEndpoint"], "port": instance["Endpoint"]["Port"],
                        "username": "admin"}, (
        f"the attached secret's connection fields are {attached!r}, expected the instance's"
    )


#: The delivery stream's S3 destination as the app declares it: a 60 s / 1 MiB buffer, GZIP.
_DECLARED_BUFFERING = {"IntervalInSeconds": 60, "SizeInMBs": 1}
_DECLARED_COMPRESSION = "GZIP"


def _assert_delivery_stream_buffers_into_bucket(ctx, out) -> None:
    """The active delivery stream the metric stream feeds holds the declared buffering hints and
    compression for its destination bucket, exactly as DescribeDeliveryStream echoes them."""
    stream = out["FirehoseDeliveryStreamName"]
    bucket = out["FirehoseDestinationBucketName"]
    description = ctx.client("firehose", region=_REGION).describe_delivery_stream(
        DeliveryStreamName=stream)["DeliveryStreamDescription"]
    status = description["DeliveryStreamStatus"]
    assert status == "ACTIVE", f"delivery stream {stream!r} is {status!r}"
    metric_stream = ctx.client("cloudwatch", region=_REGION).get_metric_stream(
        Name=out["MetricStreamName"])
    assert metric_stream["FirehoseArn"].endswith(f":deliverystream/{stream}"), metric_stream
    destinations = description["Destinations"]
    assert len(destinations) == 1, f"delivery stream {stream!r} has destinations {destinations!r}"
    s3_destination = destinations[0]["S3DestinationDescription"]
    got = (s3_destination["BucketARN"], s3_destination["BufferingHints"],
           s3_destination["CompressionFormat"])
    want = (f"arn:aws:s3:::{bucket}", _DECLARED_BUFFERING, _DECLARED_COMPRESSION)
    assert got == want, f"delivery stream {stream!r} destination is {got!r}, expected {want!r}"


def _assert_workgroup_writes_results(ctx, out) -> None:
    """A query in the workgroup writes its result under the workgroup's output location."""
    athena = ctx.client("athena", region=_REGION)
    workgroup = out["AthenaWorkgroupName"]
    location = out["AthenaOutputLocation"]
    query_id = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=workgroup)[
        "QueryExecutionId"]
    execution = _poll_until(
        ctx, lambda: athena.get_query_execution(QueryExecutionId=query_id)["QueryExecution"],
        lambda e: e["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=180.0, description=f"query {query_id} to finish")
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]
    result = execution["ResultConfiguration"]["OutputLocation"]
    assert result == f"{location}{query_id}.csv", (
        f"the query wrote to {result!r}, expected under the workgroup's {location!r}"
    )
    key = result.removeprefix(f"s3://{out['AnalysisDataBucketName']}/")
    ctx.client("s3", region=_REGION).head_object(Bucket=out["AnalysisDataBucketName"], Key=key)


def _assert_service_behind_alb(ctx, out) -> None:
    """The Fargate service runs both tasks and both are healthy targets of the internal ALB."""
    elbv2 = ctx.client("elbv2", region=_REGION)
    listeners = elbv2.describe_listeners(LoadBalancerArn=_alb_arn(ctx, out))["Listeners"]
    forwards = [
        (lst["Port"], a.get("TargetGroupArn"))
        for lst in listeners for a in lst["DefaultActions"] if a["Type"] == "forward"
    ]
    assert forwards == [(80, out["TargetGroupArn"])], (
        f"the ALB's forward listeners are {forwards!r}, expected port 80 to the service's group"
    )
    health = _poll_until(
        ctx, lambda: elbv2.describe_target_health(
            TargetGroupArn=out["TargetGroupArn"])["TargetHealthDescriptions"],
        lambda ts: len(ts) == 2 and all(t["TargetHealth"]["State"] == "healthy" for t in ts),
        timeout_s=600.0, description="both service tasks to be healthy targets")
    states = sorted(t["TargetHealth"]["State"] for t in health)
    assert states == ["healthy", "healthy"], f"target health is {health!r}"
    ecs = ctx.client("ecs", region=_REGION)
    service = _poll_until(
        ctx, lambda: ecs.describe_services(
            cluster=out["EcsClusterName"], services=[out["EcsServiceArn"]])["services"][0],
        lambda s: s["runningCount"] == s["desiredCount"] == 2,
        timeout_s=300.0, description=f"service {out['EcsServiceName']} to run 2 tasks")
    assert service["runningCount"] == service["desiredCount"] == 2, (
        f"service {out['EcsServiceName']!r} runs {service['runningCount']!r} of "
        f"{service['desiredCount']!r} tasks, expected 2 of 2"
    )


def _alb_arn(ctx, out) -> str:
    """The ARN of the load balancer the service's target group serves."""
    elbv2 = ctx.client("elbv2", region=_REGION)
    group = elbv2.describe_target_groups(
        TargetGroupArns=[out["TargetGroupArn"]])["TargetGroups"][0]
    assert len(group["LoadBalancerArns"]) == 1, group
    arn = str(group["LoadBalancerArns"][0])
    scheme = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["Scheme"]
    assert scheme == "internal", f"the service's load balancer {arn!r} has scheme {scheme!r}"
    return arn


def _assert_owned_resources_gone(ctx, outputs) -> None:
    """A sample of what the stacks owned, each answering not-found after destroy."""
    probes = [
        ("firehose destination bucket",
         lambda: ctx.client("s3", region=_REGION).head_bucket(
             Bucket=outputs["Monitoring"]["FirehoseDestinationBucketName"]),
         ("404",)),
        ("event-logs table",
         lambda: ctx.client("dynamodb", region=_REGION).describe_table(
             TableName=outputs["Database"]["EventLogsTableName"]),
         ("ResourceNotFoundException",)),
        ("database instance",
         lambda: ctx.client("rds", region=_REGION).describe_db_instances(
             DBInstanceIdentifier=outputs["Database"]["RdsInstanceId"]),
         ("DBInstanceNotFound",)),
        ("document cluster",
         lambda: ctx.client("docdb", region=_REGION).describe_db_clusters(
             DBClusterIdentifier=outputs["DocDBAthenaNLB"]["DocDbClusterName"]),
         ("DBClusterNotFoundFault",)),
        ("aliased function",
         lambda: ctx.client("lambda", region=_REGION).get_function(
             FunctionName=outputs["LambdaMisc"]["ConcurrentLambdaName"]),
         ("ResourceNotFoundException",)),
        ("exporter role",
         lambda: ctx.client("iam", region=_REGION).get_role(
             RoleName=outputs["LambdaMisc"]["ExporterRoleName"]),
         ("NoSuchEntity",)),
        ("read-only role",
         lambda: ctx.client("iam", region=_REGION).get_role(
             RoleName=outputs["AccessRoles"]["ReadOnlyRoleName"]),
         ("NoSuchEntity",)),
    ]
    for label, probe, codes in probes:
        code, _ = _error(f"{label} probe", probe)
        assert code in codes, f"after destroy, the {label} answered {code!r}, expected {codes!r}"


def _zones(ec2) -> list[str]:
    """Standard availability zones, sorted: no local or wavelength zones, none needing opt-in."""
    zones = ec2.describe_availability_zones()["AvailabilityZones"]
    return sorted(
        z["ZoneName"]
        for z in zones
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
        and z.get("OptInStatus", "opt-in-not-required") == "opt-in-not-required"
    )


def _physical_ids(state, part: str, resource_type: str, logical_prefix: str = "") -> list[str]:
    """The recorded physical ids of `resource_type` in the stack `part`, by logical-id prefix."""
    return [pid for rtype, pid, lid in state["resources"].get(part, [])
            if rtype == resource_type and lid.startswith(logical_prefix)]


def _record_resources(ctx, state) -> None:
    """Record every stack's (type, physical id, logical id), merged so a deleted stack keeps it.

    A stack is read by its id once known, which still lists a deleted stack's resources.
    """
    cfn = ctx.client("cloudformation", region=_REGION)
    ids = state.setdefault("stack_ids", {})
    for part, name in state["stacks"].items():
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


def _wait_log_line(ctx, logs, log_group: str, needle: str) -> None:
    """Poll the log group until a line contains `needle`."""
    lines = _poll_until(ctx, lambda: _log_lines(logs, log_group, needle), bool, timeout_s=180.0,
                        description=f"{needle} in {log_group}")
    assert lines, f"no line in {log_group!r} contains {needle!r}"


def _log_lines(logs, log_group: str, needle: str) -> list[str]:
    """Every message in `log_group` that contains `needle`; an absent group has none yet."""
    try:
        return [
            e["message"]
            for page in logs.get_paginator("filter_log_events").paginate(
                logGroupName=log_group, filterPattern=f'"{needle}"')
            for e in page["events"]
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _raise_if_budget_spent(ctx, what: str) -> None:
    """A wait the run budget ended is not graded."""
    if _budget_spent(ctx):
        raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")


def _poll_until(ctx, probe, predicate, *, timeout_s: float, description: str):
    """Poll probe() every 2 s until predicate(result) holds; return the final result."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(_POLL_S)
        last = probe()
    if not predicate(last):
        _raise_if_budget_spent(ctx, description)
    return last


def _error(label: str, fn) -> tuple[str, str]:
    """The AWS `(code, message)` a call raises; raises naming `label` if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"the {label} call succeeded but was expected to be refused")


def _stack_missing(exc: ClientError) -> bool:
    """True only for CloudFormation's own not-found refusal for a stack name."""
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
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
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-est-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{state['account']}/{_REGION}",
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
    """Run the CDK CLI in *work* with the app's context; asserts it exits 0."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, *_CDK_FLAGS, "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    _run_cli(ctx, cmd, work, timeout_s, f"`cdk {' '.join(args[:2])}`")


def _run_cli(ctx, cmd: list[str], cwd: Path, timeout_s: float, what: str) -> None:
    """Run `cmd` in `cwd` under the run budget; asserts it exits 0, quoting the output tail."""
    try:
        # The CLI's own default region follows the estate's, whatever the runner's region is.
        env = {**ctx.subprocess_env(), "AWS_REGION": _REGION, "AWS_DEFAULT_REGION": _REGION}
        result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True,
                                timeout=_budget_s(ctx, timeout_s))
    except subprocess.TimeoutExpired:
        _raise_if_budget_spent(ctx, what)
        raise
    assert result.returncode == 0, (
        f"{what} exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1500:]!r}"
    )


def _delete_stacks_and_wait(ctx, names: list[str], timeout_s: float, before_retry=None) -> None:
    """Delete every stack in *names* at once and poll all of them to gone.

    A stack that reaches DELETE_FAILED is deleted once more, after ``before_retry(name)``, once
    the others settle; raises naming every stack still not gone.
    """
    failed = _delete_and_settle(ctx, names, timeout_s)
    if failed and before_retry is not None:
        for name in failed:
            before_retry(name)
        failed = _delete_and_settle(ctx, failed, timeout_s)
    if failed:
        raise AssertionError(f"stacks {failed!r} were not deleted during teardown")


def _delete_and_settle(ctx, names: list[str], timeout_s: float) -> list[str]:
    """Delete *names* and wait until each is gone or DELETE_FAILED; the ones not gone."""
    cfn = ctx.client("cloudformation", region=_REGION)
    pending = []
    for name in names:
        try:
            cfn.delete_stack(StackName=name)
            pending.append(name)
        except ClientError as exc:
            if not _stack_missing(exc):
                raise
    failed: list[str] = []
    deadline = time.monotonic() + timeout_s
    while pending and time.monotonic() <= deadline:
        for name in list(pending):
            try:
                status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            except ClientError as exc:
                if not _stack_missing(exc):
                    raise
                status = "DELETE_COMPLETE"
            if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
                pending.remove(name)
                if status == "DELETE_FAILED":
                    failed.append(name)
        if pending:
            time.sleep(_POLL_S)
    return failed + pending


def _empty_and_delete_bucket(ctx, bucket: str, *, delete: bool = True) -> None:
    """Purge every version and delete marker, then (unless told not to) the bucket."""
    s3 = ctx.client("s3", region=_REGION)
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
    """Delete log group `name` until `reads` consecutive reads find it absent."""
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


def _delete_secret(ctx, arn: str) -> None:
    """Delete a secret the stack left scheduled for deletion, without a recovery window."""
    try:
        ctx.client("secretsmanager", region=_REGION).delete_secret(
            SecretId=arn, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _find_cloudwatch_role(state) -> None:
    """Name the retained CloudWatch role by the stack's recorded logical id, never the setting."""
    roles = _physical_ids(state, "LambdaMisc", "AWS::IAM::Role", _CLOUDWATCH_ROLE_LOGICAL_ID)
    assert len(roles) <= 1, f"more than one {_CLOUDWATCH_ROLE_LOGICAL_ID}* role: {roles!r}"
    if roles:
        state["cloudwatch_role"] = roles[0]


def _restore_cloudwatch_role(ctx, state) -> None:
    """Set API Gateway's account CloudWatch role back to its prior value; "" clears it."""
    apigw = ctx.client("apigateway", region=_REGION)
    prior = state["prior_cloudwatch_role"]
    apigw.update_account(patchOperations=[
        {"op": "replace", "path": "/cloudwatchRoleArn", "value": prior}])
    current = apigw.get_account().get("cloudwatchRoleArn", "")
    assert current == prior, (
        f"API Gateway's account CloudWatch role is {current!r} after restoring {prior!r}"
    )


def _delete_role(ctx, name: str) -> None:
    """Detach and drop a role's policies, then the role; tolerates only not-found."""
    iam = ctx.client("iam", region=_REGION)
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


def _bootstrap_remnants(ctx, state) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    qualifier, account = state["qualifier"], state["account"]
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation", region=_REGION).describe_stacks(
            StackName=state["toolkit"])["Stacks"][0]["StackStatus"]
        if status != "DELETE_COMPLETE":
            remaining.append(f"toolkit stack {state['toolkit']} in {status}")
    except ClientError as exc:
        if not _stack_missing(exc):
            raise
    try:
        ctx.client("s3", region=_REGION).head_bucket(Bucket=state["staging"])
        remaining.append(f"staging bucket {state['staging']}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise
    try:
        ctx.client("ssm", region=_REGION).get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append("bootstrap version parameter")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    repository = f"cdk-{qualifier}-container-assets-{account}-{_REGION}"
    try:
        ctx.client("ecr", region=_REGION).describe_repositories(repositoryNames=[repository])
        remaining.append(f"container assets repository {repository}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise
    iam = ctx.client("iam", region=_REGION)
    roles = [role["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for role in page["Roles"] if role["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _stop_metric_stream(ctx, name: str) -> None:
    """Stop one metric stream; a stream that is already gone is fine."""
    try:
        ctx.client("cloudwatch", region=_REGION).stop_metric_streams(Names=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_task_definition(ctx, arn: str) -> None:
    """Delete one deregistered task definition revision; raises on any reported failure."""
    failures = ctx.client("ecs", region=_REGION).delete_task_definitions(
        taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise AssertionError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _teardown(ctx, state) -> None:
    """Run every teardown step, collecting each failure; raise naming all of them."""
    errors: list[str] = []
    for label, fn in _teardown_steps(ctx, state, errors):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — collected and raised below, never swallowed
            errors.append(f"{label}: {exc!r}")
    if errors:
        raise AssertionError("teardown left residue: " + "; ".join(errors))


def _teardown_steps(ctx, state, errors: list[str]):
    """Yield ``(label, step)`` in order: the app stacks, what they retain or leave behind, then
    bootstrap itself; ``errors`` holds the failed steps."""
    end = time.monotonic() + _TEARDOWN_S

    def left(reserve: float = 0.0) -> float:
        return max(1.0, end - reserve - time.monotonic())

    stacks = state["stacks"]
    yield "stack resource inventory", lambda: _record_resources(ctx, state)
    yield "API Gateway account CloudWatch role lookup", lambda: _find_cloudwatch_role(state)
    # The cheap steps first, so a teardown cut short by its own deadline has done them: the
    # account-wide setting, and the metric streams that keep refilling the delivery bucket.
    yield ("API Gateway account CloudWatch role setting",
           lambda: _restore_cloudwatch_role(ctx, state))
    for name in _physical_ids(state, "Monitoring", "AWS::CloudWatch::MetricStream"):
        yield f"metric stream {name}", lambda name=name: _stop_metric_stream(ctx, name)
    parts = {name: part for part, name in stacks.items()}

    def empty_buckets(name: str) -> None:
        # A bucket refilled after its auto-delete handler ran fails the stack's delete.
        for bucket in _physical_ids(state, parts[name], "AWS::S3::Bucket"):
            _empty_and_delete_bucket(ctx, bucket, delete=False)

    others = [name for part, name in stacks.items() if part != "Networking"]
    failed_before = len(errors)
    yield (f"app stacks {others}",
           lambda: _delete_stacks_and_wait(ctx, others, left(_AFTER_STACKS_S), empty_buckets))
    yield (f"app stack {stacks['Networking']}",
           lambda: _delete_stacks_and_wait(ctx, [stacks["Networking"]], left(_AFTER_STACKS_S),
                                           empty_buckets))
    apps_gone = len(errors) == failed_before
    # A stack a timed-out deploy kept creating may hold resources the first inventory missed.
    yield "stack resource inventory after delete", lambda: _record_resources(ctx, state)
    yield ("API Gateway account CloudWatch role lookup after delete",
           lambda: _find_cloudwatch_role(state))
    # Again once the stacks are gone: a deploy still running at the first restore may have set it.
    yield ("API Gateway account CloudWatch role setting after delete",
           lambda: _restore_cloudwatch_role(ctx, state))
    if state["cloudwatch_role"]:
        role = state["cloudwatch_role"]
        yield f"retained role {role}", lambda: _delete_role(ctx, role)
    for part in stacks:
        for arn in _physical_ids(state, part, "AWS::SecretsManager::Secret"):
            yield f"secret {arn}", lambda arn=arn: _delete_secret(ctx, arn)
    # Deleting a stack only deregisters its task definitions; INACTIVE revisions stay listed.
    for arn in _physical_ids(state, "ECS", "AWS::ECS::TaskDefinition"):
        yield f"task definition {arn}", lambda arn=arn: _delete_task_definition(ctx, arn)
    logs = ctx.client("logs", region=_REGION)
    log_groups = [f"/aws/lambda/{fn}" for part in stacks
                  for fn in _physical_ids(state, part, "AWS::Lambda::Function")]
    log_groups += [f"/aws/ecs/containerinsights/{cluster}/performance"
                   for cluster in _physical_ids(state, "ECS", "AWS::ECS::Cluster")]
    for name in log_groups:
        yield (f"log group {name}",
               # Never below the time its three absent reads take, so a gone group is not residue.
               lambda name=name: _reap_log_group(
                   logs, name, budget_s=max(10.0, min(180.0, left(120.0)))))

    if apps_gone:
        yield (f"staging bucket {state['staging']}",
               lambda: _empty_and_delete_bucket(ctx, state["staging"]))
        yield (f"toolkit stack {state['toolkit']}",
               lambda: _delete_stacks_and_wait(ctx, [state["toolkit"]], min(900.0, left())))
    else:
        # A leftover app stack still needs the toolkit's cfn-exec role to be deleted later.
        yield "toolkit stack", lambda: _kept_toolkit(state)
    yield "bootstrap remnants", lambda: _assert_no_bootstrap_remnants(ctx, state)


def _kept_toolkit(state) -> None:
    """The toolkit outlives a stack that was not deleted, which still needs its exec role."""
    raise AssertionError(f"staging bucket {state['staging']} and toolkit stack "
                         f"{state['toolkit']} kept: an app stack was not deleted")


def _assert_no_bootstrap_remnants(ctx, state) -> None:
    """Nothing bootstrap created is left."""
    remaining = _bootstrap_remnants(ctx, state)
    assert not remaining, f"bootstrap remnants still present: {remaining!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
