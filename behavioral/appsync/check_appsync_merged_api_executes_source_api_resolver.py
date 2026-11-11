"""appsync-merged-api-executes-source-api-resolver."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-merged-api-executes-source-api-resolver"
GROUP = 'end-to-end'
SERVICES = ['appsync']

SDL = """schema { query: Query }
type Query {
    sourceOnly: String
}
"""

JS_MARKER = """export function request(ctx) {
  return { payload: { marker: '%s' } };
}

export function response(ctx) {
  return ctx.result.marker;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    data = json.dumps(payload).encode()
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    for lister, remover, key in (
        ("list_attached_role_policies", "detach_role_policy", "AttachedPolicies"),
        ("list_role_policies", "delete_role_policy", "PolicyNames"),
    ):
        try:
            items = getattr(iam, lister)(RoleName=role_name).get(key, [])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            continue
        for item in items:
            try:
                if key == "AttachedPolicies":
                    remover_kw = {"PolicyArn": item["PolicyArn"]}
                else:
                    remover_kw = {"PolicyName": item}
                getattr(iam, remover)(RoleName=role_name, **remover_kw)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, trust_service, inline_policy):
    """Create an IAM role trusted by ``trust_service`` and register its teardown.

    IAM exposes no condition reporting that a trust policy has become effective, so every first
    use of the role carries its own bounded retry instead of a wait here.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-role-")
    resp = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                        PolicyDocument=json.dumps(inline_policy))
    return resp["Role"]["Arn"]


def _create_merged_api_with_retry(svc, name, role_arn, timeout_s=60.0):
    """CreateGraphqlApi(apiType=MERGED) is the execution role's first use: it refuses with
    BadRequestException until the just-created role has propagated, so retry that refusal within
    a bounded window. Every other error, and a refusal past the deadline, propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return svc.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


_MERGE_TERMINAL = ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED")


def _merge_with_role_retry(ctx, svc, merged_id, association_id, role_arn, retry_s=60.0):
    """Wait for the association's merge to settle; return the settled association.

    The merge is the first time AppSync assumes the just-created execution role. Until the trust
    policy propagates, the merge settles in a failure status whose detail is AppSync's refusal to
    assume ``role_arn``; only that refusal starts the merge again, up to a deadline.
    Any other terminal status is returned as is."""
    deadline = time.monotonic() + retry_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        settled = _poll_until(
            lambda: svc.get_source_api_association(
                mergedApiIdentifier=merged_id, associationId=association_id
            )["sourceApiAssociation"],
            lambda a: a["sourceApiAssociationStatus"] in _MERGE_TERMINAL,
            timeout_s=150.0, interval_s=3.0,
            description="the association reaching a terminal merge status",
        )
        detail = settled.get("sourceApiAssociationStatusDetail") or ""
        role_not_assumable = (
            settled["sourceApiAssociationStatus"] in ("MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED")
            and detail.endswith(f"is not authorized to perform: sts:AssumeRole on resource: {role_arn}")
        )
        if not role_not_assumable or time.monotonic() >= deadline:
            return settled
        time.sleep(2.0)
        svc.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_id)


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A query at the merged API's own endpoint is answered by the source API's resolver, and the
    composed merged schema exposes the source-only field.
    """
    svc = ctx.client("appsync")
    marker = ctx.unique_name("srcmark-")

    source = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    source_id, source_arn = source["apiId"], source["arn"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=source_id))
    source_uri = (source.get("uris") or {})["GRAPHQL"]

    svc.start_schema_creation(apiId=source_id, definition=SDL.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=source_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=120.0, interval_s=2.0,
        description="the source API's schema creation reaching a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"the source schema did not build: {status!r}"
    )

    ds = svc.create_data_source(
        apiId=source_id, name=_alnum(ctx, "ds"), type="NONE"
    )["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=source_id, name=_n))
    svc.create_resolver(
        apiId=source_id, typeName="Query", fieldName="sourceOnly",
        kind="UNIT", dataSourceName=ds["name"], runtime=APPSYNC_JS,
        code=JS_MARKER % marker,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=source_id, typeName="Query", fieldName="sourceOnly")
    )
    source_key = svc.create_api_key(
        apiId=source_id, description="sim2real-behav appsync source key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=source_id, id=source_key))

    exec_role_arn = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["appsync:SourceGraphQL"],
             "Resource": [source_arn, source_arn + "/*"]},
            {"Effect": "Allow", "Action": ["appsync:StartSchemaMerge"],
             "Resource": f"arn:aws:appsync:{ctx.region}:"
                         f"{ctx.client('sts').get_caller_identity()['Account']}"
                         f":apis/*/sourceApiAssociations/*"},
        ],
    })

    merged = _create_merged_api_with_retry(
        svc, ctx.unique_name("sim2real-behav-appsync-merged-"), exec_role_arn
    )
    merged_id = merged["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=merged_id))
    merged_uri = (merged.get("uris") or {})["GRAPHQL"]
    assert merged["apiType"] == "MERGED", (
        f"the API was not created as a MERGED API: {merged.get('apiType')!r}"
    )
    assert merged_uri != source_uri, (
        f"the merged API reported the SOURCE endpoint, so nothing below would test a hop: "
        f"{merged_uri!r}"
    )

    association = svc.associate_merged_graphql_api(
        sourceApiIdentifier=source_id,
        mergedApiIdentifier=merged_id,
        description="sim2real-behav appsync merged association",
        sourceApiAssociationConfig={"mergeType": "AUTO_MERGE"},
    )["sourceApiAssociation"]
    association_id = association["associationId"]
    ctx.on_cleanup(
        lambda: svc.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_id, associationId=association_id
        )
    )

    settled = _merge_with_role_retry(ctx, svc, merged_id, association_id, exec_role_arn)
    assert settled["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"the schema merge did not succeed: {settled['sourceApiAssociationStatus']!r} "
        f"detail={settled.get('sourceApiAssociationStatusDetail')!r}"
    )

    merged_key = svc.create_api_key(
        apiId=merged_id, description="sim2real-behav appsync merged key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=merged_id, id=merged_key))

    # The freshly minted execution role is used for the FIRST time here, so the bounded retry
    # lives at first use of the permission rather than on the role's creation.
    status_code, merged_body = _poll_until(
        lambda: _post_json(ctx, merged_uri, {"x-api-key": merged_key},
                           {"query": "query { sourceOnly }"}),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=150.0, interval_s=5.0,
        description="the merged endpoint resolving a source-only field",
    )
    assert status_code == 200, f"the merged endpoint returned {status_code!r}: {merged_body!r}"
    assert not merged_body.get("errors"), (
        f"merged execution returned errors: {merged_body.get('errors')!r}"
    )
    assert merged_body["data"]["sourceOnly"] == marker, (
        f"the merged API did not route the field to the SOURCE API's resolver; expected the "
        f"resolver's marker {marker!r}, got {merged_body!r}"
    )

    introspection = _post_json(
        ctx, merged_uri, {"x-api-key": merged_key},
        {"query": "query { __schema { queryType { fields { name } } } }"},
    )
    assert introspection[0] == 200, f"introspection on the merged API failed: {introspection!r}"
    merged_field_names = {
        f["name"] for f in introspection[1]["data"]["__schema"]["queryType"]["fields"]
    }
    assert "sourceOnly" in merged_field_names, (
        f"the composed merged schema is missing the source field: {sorted(merged_field_names)!r}"
    )

    source_status, source_body = _post_json(
        ctx, source_uri, {"x-api-key": source_key}, {"query": "query { sourceOnly }"}
    )
    assert source_status == 200 and source_body["data"]["sourceOnly"] == marker, (
        f"the source API itself stopped answering, so the merged result cannot be attributed: "
        f"{source_status!r} {source_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
