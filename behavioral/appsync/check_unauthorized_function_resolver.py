"""unauthorized-function-resolver."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _signs(sts):
    """True once sts:GetCallerIdentity succeeds with the new key, False while it still errors."""
    try:
        sts.get_caller_identity()
    except ClientError:
        return False
    return True

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _alnum(ctx, prefix):
    """A unique name with NO hyphens — required for DataSource/Function names (``[_A-Za-z][_0-9A-Za-z]*``)."""
    return ctx.unique_name(prefix).replace("-", "_")

def _denied_client(ctx):
    """Create an IAM user with no policies and return (appsync client as that user, user ARN).

    Waits for the new key via sts:GetCallerIdentity, which any signed principal may call."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-denied-")
    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    def _cleanup_user(_u=user, _iam=iam):
        for k in _iam.list_access_keys(UserName=_u).get("AccessKeyMetadata", []):
            _iam.delete_access_key(UserName=_u, AccessKeyId=k["AccessKeyId"])
        _iam.delete_user(UserName=_u)
    ctx.on_cleanup(_cleanup_user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    creds = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    sts = ctx.client("sts", creds=creds)
    _poll_until(
        lambda: _signs(sts),
        lambda ok: ok,
        timeout_s=45, interval_s=3.0,
        description="new IAM access key to propagate (sts:GetCallerIdentity stops erroring)",
    )
    return ctx.client("appsync", creds=creds), user_arn

CHECK = "unauthorized-function-resolver"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFunction and GetResolver refuse a zero-permission IAM user with AccessDeniedException and
    the exact IAM refusal message, while the owning caller reads both resources."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY")["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))

    fn = svc.create_function(
        apiId=api_id,
        name=_alnum(ctx, "fn"),
        dataSourceName=ds["name"],
        requestMappingTemplate='{"version": "2018-05-29", "operation": "Invoke"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = fn["functionId"]
    ctx.on_cleanup(lambda: svc.delete_function(apiId=api_id, functionId=function_id))

    svc.start_schema_creation(apiId=api_id, definition="schema { query: Query }\ntype Query { echo: String }".encode("utf-8"))
    _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90, interval_s=2.0, description="schema creation to reach a terminal state",
    )
    svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        dataSourceName=ds["name"],
        requestMappingTemplate='{"version": "2018-05-29", "operation": "Invoke"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo"))

    # The authorized reads prove the resources exist, so the denial below is an auth boundary.
    fn_full = svc.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert fn_full["functionId"] == function_id, (
        f"GetFunction (authorized): expected functionId {function_id}, got {fn_full.get('functionId')}"
    )
    resolver_full = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert resolver_full["fieldName"] == "echo", (
        f"GetResolver (authorized): expected fieldName 'echo', got {resolver_full.get('fieldName')}"
    )

    denied, denied_arn = _denied_client(ctx)
    # The refusal names the caller and the AppSync resource path, built from the api's own ARN.
    api_path = api["arn"].split(":apis/")[0] + f":/v1/apis/{api_id}"

    # The model lists only UnauthorizedException for these ops; the service sends AccessDenied.
    code_fn, msg_fn = _error(lambda: denied.get_function(apiId=api_id, functionId=function_id))
    assert code_fn == "AccessDeniedException", (
        f"GetFunction: expected AccessDeniedException for an unauthorized principal, got {code_fn}"
    )
    assert msg_fn == (
        f"User: {denied_arn} is not authorized to perform: appsync:GetFunction on resource: "
        f"{api_path}/functions/{function_id} because no identity-based policy allows the "
        "appsync:GetFunction action"
    ), f"GetFunction: unexpected message: {msg_fn!r}"

    code_res, msg_res = _error(lambda: denied.get_resolver(apiId=api_id, typeName="Query", fieldName="echo"))
    assert code_res == "AccessDeniedException", (
        f"GetResolver: expected AccessDeniedException for an unauthorized principal, got {code_res}"
    )
    assert msg_res == (
        f"User: {denied_arn} is not authorized to perform: appsync:GetResolver on resource: "
        f"{api_path}/types/Query/resolvers/echo because no identity-based policy allows the "
        "appsync:GetResolver action"
    ), f"GetResolver: unexpected message: {msg_res!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
