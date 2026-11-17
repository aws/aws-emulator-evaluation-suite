"""create-function-code-size-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-code-size-limit"
GROUP = "functions"
SERVICES = ["appsync"]

_LIMIT = 32768
_RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
_BASE_CODE = (
    "export function request(ctx) { return {}; }\n"
    "export function response(ctx) { return ctx.result; }\n"
    "// "
)


def _code(size: int) -> str:
    pad = size - len(_BASE_CODE.encode("utf-8"))
    assert pad >= 0, f"base code already exceeds {size} bytes"
    return _BASE_CODE + ("a" * pad)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction accepts APPSYNC_JS code up to the 32,768-byte-per-function ceiling and
    rejects one byte more, creating nothing for the rejected call."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "behavioral"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    ds_name = ctx.unique_name("sim2real_behav_appsync_ds_").replace("-", "_")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))

    ok_name = ctx.unique_name("sim2real_behav_appsync_fn_ok_").replace("-", "_")
    created = svc.create_function(
        apiId=api_id,
        name=ok_name,
        dataSourceName=ds_name,
        runtime=_RUNTIME,
        code=_code(_LIMIT),
    )["functionConfiguration"]
    ctx.on_cleanup(lambda: svc.delete_function(apiId=api_id, functionId=created["functionId"]))

    over_name = ctx.unique_name("sim2real_behav_appsync_fn_over_").replace("-", "_")
    code, message = _error(
        lambda: svc.create_function(
            apiId=api_id,
            name=over_name,
            dataSourceName=ds_name,
            runtime=_RUNTIME,
            code=_code(_LIMIT + 1),
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException once the per-function code size ceiling of {_LIMIT} "
        f"bytes is exceeded, got {code}: {message!r}"
    )
    assert message == f"Code must be {_LIMIT} bytes or less", (
        f"expected AWS's exact ceiling message naming the {_LIMIT}-byte limit, got {message!r}"
    )

    names = {
        fn["name"]
        for page in svc.get_paginator("list_functions").paginate(apiId=api_id)
        for fn in page["functions"]
    }
    assert names == {ok_name}, (
        f"the rejected CreateFunction must create nothing: expected only {ok_name!r} to be "
        f"listed, got {sorted(names)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
