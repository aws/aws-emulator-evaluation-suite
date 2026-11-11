#!/usr/bin/env python3
"""CDK app: an authenticated GraphQL application -- AppSync with a Cognito user-pool authorizer over
a DynamoDB resolver, its request log group, a metric filter over that group and an alarm on the
resulting metric.

Built on the L1 AppSync constructs on purpose: the L2 `GraphqlApi` takes its schema through
`SchemaFile.from_asset`, which is a FILE ASSET and the asset-free deploy path rejects it.
`CfnGraphQLSchema` accepts the SDL inline and `CfnResolver` accepts the VTL inline, so nothing here
needs a bootstrapped environment.

The request log group is DECLARED with AppSync's own naming convention (`/aws/appsync/apis/<apiId>`,
resolved from the API's attribute) rather than left to AppSync to create lazily on the first
request. Two things depend on that: a metric filter cannot be created against a log group that does
not exist yet, and the teardown leg can only assert the group is gone if the stack owns it.

Context values (`cdk synth --context key=value`):
  variant           "ok" | "deny_putitem". The broken variant gives the data source's service role
                    dynamodb:GetItem but not dynamodb:PutItem, so the API, the authorizer and the
                    resolver are all intact and only the write is refused -- and the Query resolver
                    over the same role is the control.
  api_name / pool_name / client_name / table_name / alarm_name  explicit physical names, so the
                    update/drift leg can tell a modification from a replacement.
  metric_namespace  the namespace the metric filter publishes into.
  stage_label       stamped into every item by the mutation's VTL, so the drift leg can prove the
                    NEW resolver template is the one serving requests.
  alerts_queue_arn  an out-of-stack queue subscribed to the alarm topic.
"""
from aws_cdk import App, CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_appsync as appsync
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs
from aws_cdk import aws_sns as sns

SCHEMA_SDL = """
type Note {
  id: ID!
  text: String
  owner: String
  label: String
}

type Query {
  getNote(id: ID!): Note
}

type Mutation {
  addNote(id: ID!, text: String!): Note
}

schema {
  query: Query
  mutation: Mutation
}
"""

ADD_NOTE_REQUEST = """
{
  "version": "2018-05-29",
  "operation": "PutItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) },
  "attributeValues": {
    "text": $util.dynamodb.toDynamoDBJson($ctx.args.text),
    "owner": $util.dynamodb.toDynamoDBJson($ctx.identity.username),
    "label": $util.dynamodb.toDynamoDBJson("__LABEL__")
  }
}
"""

GET_NOTE_REQUEST = """
{
  "version": "2018-05-29",
  "operation": "GetItem",
  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) }
}
"""

# Must raise $ctx.error before returning the result. A bare `$util.toJson($ctx.result)`
# pass-through SWALLOWS a denied data-source call: real AppSync returns `null` with an empty
# top-level `errors` array, confirmed via the structured request log's ResponseMapping entry
# (`context.error` populated, `fieldInError: false`, `errors: []`) while the GraphQL response
# itself carried none. A check asserting that a denial surfaces as a GraphQL error cannot pass
# against the bare form, and worse, would read as a fidelity failure rather than a template bug.
RESPONSE_TEMPLATE = """#if($ctx.error)
  $util.error($ctx.error.message, $ctx.error.type)
#end
$util.toJson($ctx.result)
"""


class GraphqlAppStack(Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        ctx = self.node.try_get_context
        variant = ctx("variant") or "ok"
        api_name = ctx("api_name")
        pool_name = ctx("pool_name")
        client_name = ctx("client_name")
        table_name = ctx("table_name")
        alarm_name = ctx("alarm_name")
        metric_namespace = ctx("metric_namespace")
        stage_label = ctx("stage_label") or "v1"

        pool = cognito.UserPool(
            self,
            "Users",
            user_pool_name=pool_name,
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(username=True),
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_digits=True,
                require_lowercase=True,
                require_uppercase=True,
                require_symbols=True,
            ),
            # DESTROY, not the construct's RETAIN default: the teardown leg asserts the pool is
            # gone, and a retained pool is an untagged leak.
            removal_policy=RemovalPolicy.DESTROY,
        )
        client = pool.add_client(
            "AppClient",
            user_pool_client_name=client_name,
            generate_secret=False,
            # USER_PASSWORD_AUTH so the check can mint an id token from a password it set itself;
            # SRP would need a client-side protocol implementation inside the check.
            auth_flows=cognito.AuthFlow(user_password=True, admin_user_password=True),
        )

        table = dynamodb.Table(
            self,
            "Notes",
            table_name=table_name,
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        log_role = iam.Role(
            self,
            "ApiLogRole",
            assumed_by=iam.ServicePrincipal("appsync.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSAppSyncPushToCloudWatchLogs"
                )
            ],
        )
        api = appsync.CfnGraphQLApi(
            self,
            "Api",
            name=api_name,
            authentication_type="AMAZON_COGNITO_USER_POOLS",
            user_pool_config=appsync.CfnGraphQLApi.UserPoolConfigProperty(
                user_pool_id=pool.user_pool_id,
                aws_region=self.region,
                default_action="ALLOW",
            ),
            log_config=appsync.CfnGraphQLApi.LogConfigProperty(
                cloud_watch_logs_role_arn=log_role.role_arn,
                field_log_level="ALL",
                exclude_verbose_content=False,
            ),
        )
        schema = appsync.CfnGraphQLSchema(
            self, "Schema", api_id=api.attr_api_id, definition=SCHEMA_SDL
        )

        ds_role = iam.Role(
            self, "DataSourceRole", assumed_by=iam.ServicePrincipal("appsync.amazonaws.com")
        )
        ds_actions = ["dynamodb:GetItem", "dynamodb:Query"]
        if variant == "ok":
            ds_actions = ["dynamodb:PutItem", *ds_actions]
        # else: the broken variant keeps the read actions, so the Query resolver over the SAME role
        # is the control that isolates the refusal to the write.
        ds_role.add_to_policy(
            iam.PolicyStatement(
                actions=ds_actions, resources=[table.table_arn, f"{table.table_arn}/index/*"]
            )
        )
        data_source = appsync.CfnDataSource(
            self,
            "NotesSource",
            api_id=api.attr_api_id,
            name="NotesTable",
            type="AMAZON_DYNAMODB",
            service_role_arn=ds_role.role_arn,
            dynamo_db_config=appsync.CfnDataSource.DynamoDBConfigProperty(
                table_name=table.table_name, aws_region=self.region
            ),
        )

        add_note = appsync.CfnResolver(
            self,
            "AddNote",
            api_id=api.attr_api_id,
            type_name="Mutation",
            field_name="addNote",
            data_source_name="NotesTable",
            request_mapping_template=ADD_NOTE_REQUEST.replace("__LABEL__", stage_label),
            response_mapping_template=RESPONSE_TEMPLATE,
        )
        get_note = appsync.CfnResolver(
            self,
            "GetNote",
            api_id=api.attr_api_id,
            type_name="Query",
            field_name="getNote",
            data_source_name="NotesTable",
            request_mapping_template=GET_NOTE_REQUEST,
            response_mapping_template=RESPONSE_TEMPLATE,
        )
        for resolver in (add_note, get_note):
            resolver.node.add_dependency(schema)
            resolver.node.add_dependency(data_source)

        # AppSync's own log-group name, declared so the metric filter has something to attach to and
        # so the teardown leg has something whose deletion it can assert.
        log_group = logs.LogGroup(
            self,
            "ApiLogs",
            log_group_name=f"/aws/appsync/apis/{api.attr_api_id}",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        logs.MetricFilter(
            self,
            "RequestFilter",
            log_group=log_group,
            # The API id appears in every AppSync request log entry, so the pattern is a literal
            # term match rather than a JSON field path: no assumption about which log fields this
            # field-log-level emits.
            filter_pattern=logs.FilterPattern.literal(f'"{api.attr_api_id}"'),
            metric_namespace=metric_namespace,
            metric_name="GraphQLRequests",
            metric_value="1",
        )

        alert_topic = sns.Topic(self, "Alerts")
        sns.CfnSubscription(
            self,
            "AlertsToQueue",
            topic_arn=alert_topic.topic_arn,
            protocol="sqs",
            endpoint=ctx("alerts_queue_arn"),
        )
        alarm = cloudwatch.Alarm(
            self,
            "RequestsAlarm",
            alarm_name=alarm_name,
            metric=cloudwatch.Metric(
                namespace=metric_namespace,
                metric_name="GraphQLRequests",
                period=Duration.minutes(1),
                statistic="Sum",
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            # MISSING so the graded transition starts at INSUFFICIENT_DATA; NOT_BREACHING would
            # settle a never-fed alarm into OK first and the transition would never occur.
            treat_missing_data=cloudwatch.TreatMissingData.MISSING,
        )
        alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))

        CfnOutput(self, "ApiId", value=api.attr_api_id)
        CfnOutput(self, "GraphQLUrl", value=api.attr_graph_ql_url)
        CfnOutput(self, "ApiName", value=api_name)
        CfnOutput(self, "UserPoolId", value=pool.user_pool_id)
        CfnOutput(self, "UserPoolClientId", value=client.user_pool_client_id)
        CfnOutput(self, "TableName", value=table.table_name)
        CfnOutput(self, "LogGroupName", value=log_group.log_group_name)
        CfnOutput(self, "MetricNamespace", value=metric_namespace)
        CfnOutput(self, "AlarmName", value=alarm.alarm_name)
        CfnOutput(self, "AlertTopicArn", value=alert_topic.topic_arn)
        CfnOutput(self, "StageLabel", value=stage_label)


app = App()
GraphqlAppStack(app, "GraphqlAppStack")
app.synth()
