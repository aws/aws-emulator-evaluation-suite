"""e2e-schema-merge-cross-source-query-flow."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-schema-merge-cross-source-query-flow"
GROUP = "end-to-end"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """After StartSchemaMerge of two source APIs, each ListTypesByAssociation shows its source's
    field, the merged Query type carries both, and one query spanning both is accepted."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_arn = _create_merge_execution_role(ctx, iam)

    source1_id, source1_name = _create_source_api(ctx, appsync, field_name="greetingOne")
    source2_id, source2_name = _create_source_api(ctx, appsync, field_name="greetingTwo")

    _attach_source_graphql_policy(ctx, iam, role_arn, [source1_id, source2_id], account_id, ctx.region)

    merged_name = _safe_graphql_name(ctx, "sim2real_merged")
    merged_api = appsync.create_graphql_api(
        name=merged_name,
        authenticationType="API_KEY",
        apiType="MERGED",
        mergedApiExecutionRoleArn=role_arn,
    )["graphqlApi"]
    merged_id = merged_api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_id))

    assoc1_id = _associate_and_merge(ctx, appsync, source1_id, merged_id)
    assoc2_id = _associate_and_merge(ctx, appsync, source2_id, merged_id)

    status1 = _wait_for_merge_terminal(ctx, appsync, merged_id, assoc1_id, source1_id)
    status2 = _wait_for_merge_terminal(ctx, appsync, merged_id, assoc2_id, source2_id)
    assert status1 == "MERGE_SUCCESS", f"source1 association ended in {status1!r}"
    assert status2 == "MERGE_SUCCESS", f"source2 association ended in {status2!r}"

    types1 = appsync.list_types_by_association(
        mergedApiIdentifier=merged_id, associationId=assoc1_id, format="SDL"
    )["types"]
    types2 = appsync.list_types_by_association(
        mergedApiIdentifier=merged_id, associationId=assoc2_id, format="SDL"
    )["types"]

    query_def_1 = next(t["definition"] for t in types1 if t["name"] == "Query")
    query_def_2 = next(t["definition"] for t in types2 if t["name"] == "Query")

    assert "greetingOne" in query_def_1, query_def_1
    assert "greetingTwo" in query_def_2, query_def_2

    # The decisive read: the merged API's OWN schema (not an association's scoped view) must
    # carry BOTH sources' fields in the SAME Query type. Two association-scoped views passing
    # independently cannot rule out one source's contribution having clobbered the other's in
    # the schema the merged API actually serves.
    merged_query_def = appsync.get_type(apiId=merged_id, typeName="Query", format="SDL")["type"]["definition"]
    assert "greetingOne" in merged_query_def, merged_query_def
    assert "greetingTwo" in merged_query_def, merged_query_def

    # And the flow the check is named for: one GraphQL query at the merged endpoint spanning
    # both sources' fields must be ACCEPTED by the composed schema -- a query the merge never
    # actually happened would reject with "Cannot query field" on at least one of them.
    merged_key = appsync.create_api_key(apiId=merged_id, description="sim2real merged key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=merged_id, id=merged_key))
    merged_uri = merged_api["uris"]["GRAPHQL"]

    status_code, body = _post_graphql(ctx, merged_uri, merged_key, "query { greetingOne greetingTwo }")
    assert status_code == 200, f"merged endpoint query failed: {status_code!r} {body!r}"
    unknown_field_errors = [
        e for e in (body.get("errors") or []) if "Cannot query field" in e.get("message", "")
    ]
    assert not unknown_field_errors, (
        f"merged schema rejected a query spanning both sources: {unknown_field_errors!r}"
    )


def _post_graphql(ctx, url: str, api_key: str, query: str, timeout_s: float = 30.0):
    """POST a GraphQL query with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    route_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        route_url,
        data=json.dumps({"query": query}).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "x-api-key": api_key, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(ctx.http_verify)) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    return status, (json.loads(raw) if raw else {})


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _safe_graphql_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c if (c.isalnum() or c == "_") else "_" for c in raw)
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = "a" + cleaned
    return cleaned[:64]


def _create_merge_execution_role(ctx, iam) -> str:
    role_name = _safe_graphql_name(ctx, "sim2real_appsync_merge")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    import json as _json

    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_json.dumps(trust_policy))["Role"]
    role_arn = role["Arn"]

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="source-graphql")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _attach_source_graphql_policy(ctx, iam, role_arn, source_api_ids, account_id, region) -> None:
    import json as _json

    role_name = role_arn.split("/")[-1]
    resources = []
    for sid in source_api_ids:
        base = f"arn:aws:appsync:{region}:{account_id}:apis/{sid}"
        resources.append(base)
        resources.append(f"{base}/*")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "appsync:SourceGraphQL", "Resource": resources}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="source-graphql", PolicyDocument=_json.dumps(policy))


def _create_source_api(ctx, appsync, field_name: str):
    name = _safe_graphql_name(ctx, f"sim2real_src_{field_name.lower()}")
    api = appsync.create_graphql_api(name=name, authenticationType="API_KEY")["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: _delete_source_api(appsync, api_id))

    schema = f"schema {{\n  query: Query\n}}\ntype Query {{\n  {field_name}: String\n}}\n"
    appsync.start_schema_creation(apiId=api_id, definition=schema.encode("utf-8"))
    _wait_for_schema_creation(ctx, appsync, api_id)
    return api_id, name


def _delete_source_api(appsync, api_id: str, timeout_s: float = 180.0) -> None:
    """Teardown: a source API refuses deletion until AppSync settles its disassociation, which runs
    asynchronously, so the delete is retried while it gives that one refusal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            appsync.delete_graphql_api(apiId=api_id)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] != "BadRequestException"
                or "associated to a Merged API" not in err.get("Message", "")
                or time.monotonic() >= deadline
            ):
                raise
        time.sleep(5)


def _wait_for_schema_creation(ctx, appsync, api_id: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError(f"schema creation failed for api {api_id}")
        time.sleep(2)
    raise AssertionError(f"schema creation for {api_id} never reached SUCCESS, last status={status!r}")


def _associate_and_merge(ctx, appsync, source_api_id: str, merged_api_id: str) -> str:
    assoc = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_api_id, mergedApiIdentifier=merged_api_id
    )["sourceApiAssociation"]
    assoc_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_api_id, associationId=assoc_id
        )
    )
    try:
        appsync.start_schema_merge(associationId=assoc_id, mergedApiIdentifier=merged_api_id)
    except Exception:
        pass  # association may already have auto-scheduled the merge
    return assoc_id


def _wait_for_merge_terminal(
    ctx, appsync, merged_api_id: str, assoc_id: str, source_api_id: str, timeout_s: float = 240.0
) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    retried = 0
    while time.monotonic() < deadline:
        detail = appsync.get_source_api_association(
            mergedApiIdentifier=merged_api_id, associationId=assoc_id
        )["sourceApiAssociation"]
        status = detail.get("sourceApiAssociationStatus")
        if status in ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"):
            # IAM role propagation to the AppSync merge service can lag briefly right after
            # put_role_policy; give it up to two extra attempts before treating a failure as
            # terminal.
            if status != "MERGE_SUCCESS" and retried < 2:
                retried += 1
                time.sleep(5)
                try:
                    appsync.start_schema_merge(associationId=assoc_id, mergedApiIdentifier=merged_api_id)
                except Exception:
                    pass
                continue
            return status
        time.sleep(5)
    raise AssertionError(f"association {assoc_id} never reached a terminal merge status, last={status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
