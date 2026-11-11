"""resolver-mapping-template-whitespace-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "resolver-mapping-template-whitespace-preserved"
GROUP = "representation"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Mapping templates with leading/trailing whitespace, blank lines, tabs and multi-byte comments
    persist byte-for-byte through CreateResolver, GetResolver and UpdateResolver, and an update
    fully replaces the old template."""
    appsync = ctx.client("appsync")

    api_name = _safe_graphql_name(ctx, "sim2real_resolverapi")
    api = appsync.create_graphql_api(
        name=api_name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    schema = "schema {\n  query: Query\n}\ntype Query {\n  probe: String\n}\n"
    appsync.start_schema_creation(apiId=api_id, definition=schema.encode("utf-8"))
    _wait_for_schema_creation(appsync, api_id)

    appsync.create_data_source(apiId=api_id, name="NoneDS", type="NONE")

    request_template_a = (
        "## comment with unicode: héllo Ñ 你好 🎉\n"
        "\n"
        "\t{\n"
        '\t  "version": "2017-02-28",\n'
        '\t  "payload": {}\n'
        "\t}\n"
        "\n"
    )
    response_template_a = '$util.toJson("value-a")\n## trailing cömment ü\n\t\n'

    created = appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="probe",
        dataSourceName="NoneDS",
        requestMappingTemplate=request_template_a,
        responseMappingTemplate=response_template_a,
    )["resolver"]
    assert created["requestMappingTemplate"] == request_template_a, repr(
        created["requestMappingTemplate"]
    )
    assert created["responseMappingTemplate"] == response_template_a, repr(
        created["responseMappingTemplate"]
    )

    fetched_a = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="probe")["resolver"]
    assert fetched_a["requestMappingTemplate"] == request_template_a, repr(fetched_a["requestMappingTemplate"])
    assert fetched_a["responseMappingTemplate"] == response_template_a, repr(
        fetched_a["responseMappingTemplate"]
    )

    request_template_b = (
        "## second template, unicode: परीक्षण 日本語\n"
        "  \n"
        "{\n"
        '  "version": "2017-02-28",\n'
        '  "payload": {}\n'
        "}\n"
        "  \n"
    )
    response_template_b = '$util.toJson("value-b")\n\n\t## another cömment\n'

    updated = appsync.update_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="probe",
        dataSourceName="NoneDS",
        requestMappingTemplate=request_template_b,
        responseMappingTemplate=response_template_b,
    )["resolver"]
    assert updated["requestMappingTemplate"] == request_template_b, repr(
        updated["requestMappingTemplate"]
    )
    assert updated["responseMappingTemplate"] == response_template_b, repr(
        updated["responseMappingTemplate"]
    )

    fetched_b = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="probe")["resolver"]
    assert fetched_b["requestMappingTemplate"] == request_template_b, repr(fetched_b["requestMappingTemplate"])
    assert fetched_b["responseMappingTemplate"] == response_template_b, repr(
        fetched_b["responseMappingTemplate"]
    )
    # The old template must be gone, not merely appended to or merged with the new one.
    assert request_template_a not in fetched_b["requestMappingTemplate"], (
        f"stale template survived update: {fetched_b['requestMappingTemplate']!r}"
    )


def _safe_graphql_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c if (c.isalnum() or c == "_") else "_" for c in raw)
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = "a" + cleaned
    return cleaned[:64]


def _wait_for_schema_creation(appsync, api_id: str, timeout_s: float = 60.0) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
