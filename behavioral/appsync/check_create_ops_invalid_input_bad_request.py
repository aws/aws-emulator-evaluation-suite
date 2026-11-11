"""create-ops-invalid-input-bad-request."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "create-ops-invalid-input-bad-request"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Create* operations with one malformed field fail BadRequestException (CreateApi: Validation-
    Exception) with exact messages and create nothing; a valid variant of each succeeds.
    """
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY"
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    svc.start_schema_creation(
        apiId=api_id, definition=b"schema { query: Query }\ntype Query { ping: String }"
    )
    _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90,
        interval_s=2.0,
        description="schema creation to reach a terminal state",
    )

    ds_name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))

    default_auth = [{"authType": "API_KEY"}]
    all_auth = [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}]
    event_api = svc.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-eventapi-"),
        eventConfig={
            "authProviders": all_auth,
            "connectionAuthModes": default_auth,
            "defaultPublishAuthModes": default_auth,
            "defaultSubscribeAuthModes": default_auth,
        },
    )["api"]
    ctx.on_cleanup(lambda _a=event_api: svc.delete_api(apiId=_a["apiId"]))
    event_api_id = event_api["apiId"]

    # CreateDataSource: name violates ^[_A-Za-z][_0-9A-Za-z]*$ (ds_name above is the valid case).
    bad_ds_name = "bad-name-with-hyphens"
    error = _error(
        lambda: svc.create_data_source(apiId=api_id, name=bad_ds_name, type="NONE")
    )
    expected = (
        "BadRequestException",
        "The data source name is invalid. Please refer to the documentation for more details.",
    )
    assert error == expected, f"CreateDataSource: expected {expected}, got {error}"
    listed = svc.list_data_sources(apiId=api_id)["dataSources"]
    assert all(ds["name"] != bad_ds_name for ds in listed), (
        f"CreateDataSource rejected input must not create a data source: found {bad_ds_name!r} "
        f"in ListDataSources"
    )

    # CreateFunction: an APPSYNC_JS runtime combined with a VTL mapping template is incompatible.
    bad_fn_name = ctx.unique_name("sim2real_behav_fn_bad_").replace("-", "_")
    error = _error(
        lambda: svc.create_function(
            apiId=api_id,
            name=bad_fn_name,
            dataSourceName=ds_name,
            runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
            requestMappingTemplate="{}",
        )
    )
    expected = (
        "BadRequestException",
        "Request and Response mapping templates can not be supplied with provided runtime.",
    )
    assert error == expected, f"CreateFunction: expected {expected}, got {error}"
    funcs = svc.list_functions(apiId=api_id)["functions"]
    assert all(f["name"] != bad_fn_name for f in funcs), (
        f"CreateFunction rejected input must not create a function: found {bad_fn_name!r} in ListFunctions"
    )

    good_fn_name = ctx.unique_name("sim2real_behav_fn_good_").replace("-", "_")
    good_fn = svc.create_function(
        apiId=api_id,
        name=good_fn_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["functionConfiguration"]
    ctx.on_cleanup(lambda _fid=good_fn["functionId"]: svc.delete_function(apiId=api_id, functionId=_fid))
    assert good_fn["name"] == good_fn_name, (
        f"CreateFunction (valid input): expected name {good_fn_name}, got {good_fn.get('name')}"
    )

    # CreateResolver: kind=UNIT with a pipelineConfig set is a config-consistency violation.
    error = _error(
        lambda: svc.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="ping",
            kind="UNIT",
            dataSourceName=ds_name,
            pipelineConfig={"functions": [str(uuid.uuid4())]},
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson($ctx.result)",
        )
    )
    expected = ("BadRequestException", "PipelineConfig should not be specified.")
    assert error == expected, f"CreateResolver: expected {expected}, got {error}"
    not_found = _error(lambda: svc.get_resolver(apiId=api_id, typeName="Query", fieldName="ping"))
    expected = ("NotFoundException", "No resolver found.")
    assert not_found == expected, (
        f"CreateResolver rejected input must not create a resolver: GetResolver expected "
        f"{expected}, got {not_found}"
    )

    good_resolver = svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        kind="UNIT",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["resolver"]
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping"))
    assert good_resolver["fieldName"] == "ping", (
        f"CreateResolver (valid input): expected fieldName 'ping', got {good_resolver.get('fieldName')}"
    )

    # CreateType: syntactically invalid SDL.
    error = _error(
        lambda: svc.create_type(
            apiId=api_id,
            definition="type Widget { id: ID this is not valid SDL !!! $$$",
            format="SDL",
        )
    )
    expected = ("BadRequestException", "Unable to parse provided type definition.")
    assert error == expected, f"CreateType: expected {expected}, got {error}"
    not_found = _error(lambda: svc.get_type(apiId=api_id, typeName="Widget", format="SDL"))
    expected = ("NotFoundException", "Type not found.")
    assert not_found == expected, (
        f"CreateType rejected input must not create a type: GetType expected {expected}, "
        f"got {not_found}"
    )

    good_type = svc.create_type(
        apiId=api_id, definition="type Sim2RealBehavGood { id: ID }", format="SDL"
    )["type"]
    ctx.on_cleanup(lambda: svc.delete_type(apiId=api_id, typeName="Sim2RealBehavGood"))
    assert good_type["name"] == "Sim2RealBehavGood", (
        f"CreateType (valid input): expected name 'Sim2RealBehavGood', got {good_type.get('name')}"
    )

    # CreateChannelNamespace: an auth mode outside the owning Event API's authProviders.
    bad_ns_name = ctx.unique_name("sim2real-behav-ns-bad-")
    error = _error(
        lambda: svc.create_channel_namespace(
            apiId=event_api_id,
            name=bad_ns_name,
            subscribeAuthModes=[{"authType": "AWS_LAMBDA"}],
            publishAuthModes=[{"authType": "API_KEY"}],
        )
    )
    expected = (
        "BadRequestException",
        "Channel namespace auth type must be present in the API's auth providers.",
    )
    assert error == expected, f"CreateChannelNamespace: expected {expected}, got {error}"
    listed = svc.list_channel_namespaces(apiId=event_api_id)["channelNamespaces"]
    assert all(ns["name"] != bad_ns_name for ns in listed), (
        f"CreateChannelNamespace rejected input must not create a namespace: found {bad_ns_name!r} "
        f"in ListChannelNamespaces"
    )

    good_ns_name = ctx.unique_name("sim2real-behav-ns-good-")
    good_ns = svc.create_channel_namespace(
        apiId=event_api_id,
        name=good_ns_name,
        subscribeAuthModes=default_auth,
        publishAuthModes=default_auth,
    )["channelNamespace"]
    ctx.on_cleanup(lambda: svc.delete_channel_namespace(apiId=event_api_id, name=good_ns_name))
    assert good_ns["name"] == good_ns_name, (
        f"CreateChannelNamespace (valid input): expected name {good_ns_name}, got {good_ns.get('name')}"
    )

    # CreateApiCache: ttl outside the documented 1-3600s range.
    error = _error(
        lambda: svc.create_api_cache(
            apiId=api_id, ttl=0, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
    )
    expected = (
        "BadRequestException",
        "TTL value cannot be smaller than 1 second and larger than 3600 seconds.",
    )
    assert error == expected, f"CreateApiCache: expected {expected}, got {error}"
    not_found = _error(lambda: svc.get_api_cache(apiId=api_id))
    expected = (
        "NotFoundException",
        "Unable to get the cache as it doesn't exist, please create the cache first.",
    )
    assert not_found == expected, (
        f"CreateApiCache rejected input must not create a cache: GetApiCache expected "
        f"{expected}, got {not_found}"
    )

    good_cache = svc.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    # No separate teardown: DeleteApiCache is refused while the cache is still being created, and
    # deleting the GraphQL API (registered above) removes its cache with it.
    assert good_cache["ttl"] == 300, (
        f"CreateApiCache (valid input): expected ttl=300, got {good_cache.get('ttl')}"
    )

    # CreateDomainName: a malformed certificateArn. No valid case: that needs a real ACM
    # certificate in us-east-1.
    bad_domain = f"{ctx.unique_name('sim2real-behav-dn-')}.example.com"
    error = _error(
        lambda: svc.create_domain_name(
            domainName=bad_domain,
            certificateArn="not-a-valid-cert-arn",
        )
    )
    expected = (
        "BadRequestException",
        "1 validation error detected: Value 'not-a-valid-cert-arn' at 'certificateArn' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "^arn:[a-z-]*:(acm|iam):[a-z0-9-]*:\\d{12}:(certificate|server-certificate)/[0-9A-Za-z_/-]*$",
    )
    assert error == expected, f"CreateDomainName: expected {expected}, got {error}"
    not_found = _error(lambda: svc.get_domain_name(domainName=bad_domain))
    expected = ("NotFoundException", "Domain name not found")
    assert not_found == expected, (
        f"CreateDomainName rejected input must not create a domain name: GetDomainName expected "
        f"{expected}, got {not_found}"
    )

    # CreateApi: a name violating the pattern surfaces as ValidationException, not
    # BadRequestException (event_api above is the valid case).
    bad_api_name = "bad!name#with*illegal(chars)"
    error = _error(
        lambda: svc.create_api(
            name=bad_api_name,
            eventConfig={
                "authProviders": [{"authType": "API_KEY"}],
                "connectionAuthModes": [{"authType": "API_KEY"}],
                "defaultPublishAuthModes": [{"authType": "API_KEY"}],
                "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
            },
        )
    )
    expected = (
        "ValidationException",
        "1 validation error detected: Value at 'name' failed to satisfy constraint: Member must "
        "satisfy regular expression pattern: [A-Za-z0-9_\\-\\ ]+",
    )
    assert error == expected, f"CreateApi: expected {expected}, got {error}"

    apis = svc.list_apis()["apis"]
    assert all(a["name"] != bad_api_name for a in apis), (
        f"CreateApi rejected input must not create an Api: found {bad_api_name!r} in ListApis"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
