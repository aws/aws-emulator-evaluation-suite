"""e2e-data-source-introspection-driven-resolver-flow."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "e2e-data-source-introspection-driven-resolver-flow"
GROUP = "data-plane"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartDataSourceIntrospection discovers an Aurora table's columns, and a resolver
    built from the discovered field names actually returns the live row through the
    GraphQL endpoint (not just a stubbed 200 on CreateResolver)."""
    rds = ctx.client("rds")
    rds_data = ctx.client("rds-data")
    secretsmanager = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    appsync = ctx.client("appsync")

    db_name = "testdb"
    table_name = "widgets"

    # ---- secret for the DB admin credentials ----
    master_user = "appsyncadmin"
    master_password = "Sim2Real-" + secrets.token_urlsafe(12).replace("-", "x")
    secret_name = ctx.unique_name("sim2real-appsync-dsi-secret-")
    secret = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": master_user, "password": master_password}),
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    # ---- Aurora Serverless v2 (MySQL) cluster with Data API enabled ----
    # The RDS Data API is provisioned on Aurora Serverless v2: a provisioned cluster plus a
    # db.serverless instance.
    cluster_id = _clean_identifier(ctx.unique_name("sim2real-appsync-dsi-"))
    instance_id = _clean_identifier(ctx.unique_name("sim2real-appsync-dsi-ix-"))
    engine_version = rds.describe_db_engine_versions(Engine="aurora-mysql", DefaultOnly=True)["DBEngineVersions"][0][
        "EngineVersion"
    ]

    try:
        created = rds.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            Engine="aurora-mysql",
            EngineVersion=engine_version,
            MasterUsername=master_user,
            MasterUserPassword=master_password,
            DatabaseName=db_name,
            EnableHttpEndpoint=True,
            ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2},
            StorageEncrypted=True,
            DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
        )
    except rds.exceptions.ClientError as exc:  # pragma: no cover - environment dependent
        raise AssertionError(f"could not create Aurora Serverless v2 cluster: {exc}") from exc
    cluster_arn = created["DBCluster"]["DBClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.serverless",
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))

    _wait_instance_available(ctx, rds, instance_id, timeout_s=1200)
    _wait_data_api_awake(ctx, rds_data, cluster_arn, secret_arn, db_name, timeout_s=180)

    rds_data.execute_statement(
        resourceArn=cluster_arn,
        secretArn=secret_arn,
        database=db_name,
        sql=f"CREATE TABLE {table_name} (id INT NOT NULL PRIMARY KEY, name VARCHAR(64) NOT NULL)",
    )
    rds_data.execute_statement(
        resourceArn=cluster_arn,
        secretArn=secret_arn,
        database=db_name,
        sql=f"INSERT INTO {table_name} (id, name) VALUES (1, 'widget-alpha')",
    )

    # ---- IAM role AppSync assumes to reach the RDS Data API + secret ----
    role_name = ctx.unique_name("sim2real-appsync-dsi-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement"],
                "Resource": cluster_arn,
            },
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="rds-data-access", PolicyDocument=json.dumps(permissions_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="rds-data-access"))

    # ---- AppSync API + RDS data source ----
    api = appsync.create_graphql_api(name=ctx.unique_name("sim2real-appsync-dsi-api-"), authenticationType="API_KEY")[
        "graphqlApi"
    ]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    api_key = appsync.create_api_key(apiId=api_id)["apiKey"]["id"]

    ds_name = "widgets_rds"
    _retry_until_role_ready(
        ctx,
        lambda: appsync.create_data_source(
            apiId=api_id,
            name=ds_name,
            type="RELATIONAL_DATABASE",
            serviceRoleArn=role_arn,
            relationalDatabaseConfig={
                "relationalDatabaseSourceType": "RDS_HTTP_ENDPOINT",
                "rdsHttpEndpointConfig": {
                    "awsRegion": ctx.region,
                    "dbClusterIdentifier": cluster_arn,
                    "databaseName": db_name,
                    "awsSecretStoreArn": secret_arn,
                },
            },
        )
    )

    # ---- start introspection against the same Data API endpoint ----
    introspection_id = appsync.start_data_source_introspection(
        rdsDataApiConfig={"databaseName": db_name, "resourceArn": cluster_arn, "secretArn": secret_arn}
    )["introspectionId"]

    model = _wait_introspection_success(ctx, appsync, introspection_id, table_name, timeout_s=180)
    discovered_fields = sorted(f["name"] for f in model["fields"])
    assert "id" in discovered_fields and "name" in discovered_fields, discovered_fields

    # ---- build a schema + resolver from the discovered fields ----
    select_cols = ", ".join(discovered_fields)
    schema_sdl = (
        "type Widget { " + " ".join(f"{f}: String" for f in discovered_fields) + " }\n"
        "type Query { getWidget(id: Int!): Widget }\n"
        "schema { query: Query }\n"
    )
    _create_schema_and_wait(ctx, appsync, api_id, schema_sdl, timeout_s=120)

    js_code = (
        "import { sql, createMySQLStatement, toJsonObject } from '@aws-appsync/utils/rds';\n"
        "export function request(ctx) {\n"
        "  const { id } = ctx.args;\n"
        f"  const statement = sql`SELECT {select_cols} FROM {table_name} WHERE id = ${{id}}`;\n"
        "  return createMySQLStatement(statement);\n"
        "}\n"
        "export function response(ctx) {\n"
        "  const rows = toJsonObject(ctx.result)[0];\n"
        "  return rows.length ? rows[0] : null;\n"
        "}\n"
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        dataSourceName=ds_name,
        code=js_code,
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
    )
    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")["resolver"]
    assert resolver["dataSourceName"] == ds_name, (ds_name, resolver["dataSourceName"])

    graphql_url = api["uris"]["GRAPHQL"]
    body = _graphql_request_with_retries(
        ctx, graphql_url, api_key, "query { getWidget(id: 1) { name } }", timeout_s=120
    )
    assert "errors" not in body, body
    assert body["data"]["getWidget"]["name"] == "widget-alpha", body


def _clean_identifier(name: str) -> str:
    return name.replace("_", "-").lower()[:63]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_instance_available(ctx, rds, instance_id: str, timeout_s: float) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]["DBInstanceStatus"]
        if status == "available":
            return
        if status in ("failed", "incompatible-parameters", "inaccessible-encryption-credentials"):
            raise AssertionError(f"instance {instance_id} entered terminal bad state: {status}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"instance {instance_id} becoming available: the run budget ended first; not graded"
        )
    raise AssertionError(f"instance {instance_id} never became available within {timeout_s}s")


def _delete_instance(rds, instance_id: str) -> None:
    """Start the instance delete; the cluster teardown waits for the member to go."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except rds.exceptions.DBInstanceNotFoundFault:
        return


def _delete_cluster(rds, cluster_id: str) -> None:
    """Delete the cluster once its deleting member instance is gone (InvalidDBClusterStateFault until then)."""
    deadline = time.monotonic() + 780.0
    last = None
    while time.monotonic() < deadline:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            return
        except rds.exceptions.InvalidDBClusterStateFault as exc:
            last = exc
            time.sleep(2.0)
        except rds.exceptions.DBClusterNotFoundFault:
            return
    raise RuntimeError(f"db cluster {cluster_id} was not deleted: {last!r}")


def _wait_data_api_awake(ctx, rds_data, cluster_arn: str, secret_arn: str, db_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_exc = None
    while time.monotonic() < deadline:
        try:
            rds_data.execute_statement(resourceArn=cluster_arn, secretArn=secret_arn, database=db_name, sql="SELECT 1")
            return
        except Exception as exc:  # noqa: BLE001 - transient wake-up errors expected
            last_exc = exc
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(
            "the RDS Data API becoming reachable: the run budget ended first; not graded"
        )
    raise AssertionError(f"RDS Data API never became reachable within {timeout_s}s: {last_exc}")


def _wait_introspection_success(ctx, appsync, introspection_id: str, table_name: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = appsync.get_data_source_introspection(introspectionId=introspection_id, includeModelsSDL=False)
        status = resp["introspectionStatus"]
        if status == "SUCCESS":
            models = resp.get("introspectionResult", {}).get("models", [])
            for m in models:
                if m["name"].lower() == table_name.lower():
                    return m
            raise AssertionError(f"table {table_name!r} not among discovered models: {[m['name'] for m in models]}")
        if status == "FAILED":
            raise AssertionError(f"introspection failed: {resp.get('introspectionStatusDetail')}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError("introspection reaching SUCCESS: the run budget ended first; not graded")
    raise AssertionError(f"introspection never reached SUCCESS within {timeout_s}s")


def _create_schema_and_wait(ctx, appsync, api_id: str, sdl: str, timeout_s: float) -> None:
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError("schema creation failed")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError("schema creation completing: the run budget ended first; not graded")
    raise AssertionError(f"schema creation never completed within {timeout_s}s")


def _retry_until_role_ready(ctx, fn, timeout_s: float = 60.0):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - IAM eventual consistency
            last_exc = exc
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(
            "the operation succeeding past IAM propagation: the run budget ended first; not graded"
        )
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


def _graphql_request_with_retries(ctx, url: str, api_key: str, query: str, timeout_s: float = 60.0) -> dict:
    """POST the query until a response carries no GraphQL errors (the data source's role
    propagates after the resolver is live); at the deadline the last error body is returned."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_exc = None
    last_body = None
    while time.monotonic() < deadline:
        try:
            routed_url, route_headers = ctx.endpoint_route(url)
            req = urllib.request.Request(
                routed_url,
                data=json.dumps({"query": query}).encode("utf-8"),
                headers={"content-type": "application/json", "x-api-key": api_key, **route_headers},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=max(1.0, min(15.0, deadline - time.monotonic()))) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            if "errors" not in body:
                return body
            last_body = body
            time.sleep(2)
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            last_exc = exc
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(
            "a GraphQL response without errors: the run budget ended first; not graded"
        )
    if last_body is not None:
        return last_body
    raise AssertionError(f"GraphQL request never succeeded within {timeout_s}s: {last_exc}")


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=840.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
