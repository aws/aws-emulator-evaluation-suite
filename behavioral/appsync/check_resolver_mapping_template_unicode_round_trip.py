"""resolver-mapping-template-unicode-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "resolver-mapping-template-unicode-round-trip"
GROUP = "resolver"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Resolver request/response VTL mapping templates with unicode and special characters
    round-trip byte-for-byte through CreateResolver/GetResolver and UpdateResolver/GetResolver."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    _create_schema(ctx, api_id)
    ds_name = _safe_name(ctx, "ds")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    request_template_1 = (
        '## comment: h\u00e9llo \u4e16\u754c \U0001f389 "quoted" \\backslash\\ \u03a9\u2248\u00e7\u221a\n'
        "{\n"
        '  "version": "2018-05-29",\n'
        '  "operation": "Invoke",\n'
        '  "payload": $util.toJson($context.arguments)\n'
        "}"
    )
    response_template_1 = "$util.toJson($context.result)"

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=request_template_1,
        responseMappingTemplate=response_template_1,
    )
    ctx.on_cleanup(
        lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo")
    )

    created = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert created["requestMappingTemplate"] == request_template_1, (
        "requestMappingTemplate mangled on create: "
        f"{created['requestMappingTemplate']!r} != {request_template_1!r}"
    )
    assert created["responseMappingTemplate"] == response_template_1, (
        "responseMappingTemplate mangled on create: "
        f"{created['responseMappingTemplate']!r} != {response_template_1!r}"
    )

    request_template_2 = (
        '## updated: \u00f1\u00f8\u03c0 \U0001f680 \u00fc\u00f1\u00ed\u00e7\u00f8d\u00e9 '
        '"double\\"quote" back\\\\slash\n'
        "{\n"
        '  "version": "2018-05-29",\n'
        '  "operation": "Invoke",\n'
        '  "payload": $util.toJson($context.arguments)\n'
        "}"
    )
    response_template_2 = "## updated response \u043a\u043b\u044e\u0447\n$util.toJson($context.result)"

    appsync.update_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=request_template_2,
        responseMappingTemplate=response_template_2,
    )

    updated = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert updated["requestMappingTemplate"] == request_template_2, (
        "requestMappingTemplate mangled on update: "
        f"{updated['requestMappingTemplate']!r} != {request_template_2!r}"
    )
    assert updated["responseMappingTemplate"] == response_template_2, (
        "responseMappingTemplate mangled on update: "
        f"{updated['responseMappingTemplate']!r} != {response_template_2!r}"
    )
    assert updated["requestMappingTemplate"] != request_template_1, (
        "requestMappingTemplate still reflects the pre-update value: "
        f"{updated['requestMappingTemplate']!r} == {request_template_1!r}"
    )


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": CHECK}
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _safe_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real{kind}")
    return "".join(c if c.isalnum() or c == "_" else "_" for c in raw)


def _create_schema(ctx, api_id: str, timeout_s: float = 90.0) -> None:
    appsync = ctx.client("appsync")
    schema_sdl = "type Query {\n  echo: String\n}\n"
    appsync.start_schema_creation(apiId=api_id, definition=schema_sdl.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError("schema creation FAILED, cannot exercise resolver round-trip")
        time.sleep(2)
    raise AssertionError(f"schema creation did not reach SUCCESS within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
