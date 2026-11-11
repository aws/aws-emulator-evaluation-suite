"""op-contract-create-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-resource"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource attaches a child under parentId with the correct path; creating a
    second resource with the same pathPart under the same parent is rejected with
    ConflictException and does not create a duplicate, while a distinct pathPart succeeds."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"),
        tags={"sim2real": "op-contract-create-resource"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    created = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    assert created["path"] == "/widgets"
    assert created["parentId"] == root_id
    resource_id = created["id"]

    # error boundary: duplicate pathPart under the same parent -> ConflictException
    err = _client_error(
        lambda: apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    )
    assert err.get("Code") == "ConflictException", f"expected ConflictException, got {err.get('Code')!r}"
    assert err.get("Message") == "Another resource with the same parent already has this name: widgets", (
        f"expected the exact duplicate-pathPart message, got {err.get('Message')!r}"
    )
    matches = [
        r for r in apigw.get_resources(restApiId=api_id)["items"] if r.get("pathPart") == "widgets"
    ]
    assert len(matches) == 1 and matches[0]["id"] == resource_id

    # positive control: a distinct pathPart under the same parent succeeds
    other = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="gadgets")
    assert other["path"] == "/gadgets"
    assert other["id"] != resource_id

    # terminal read: independent of both create_resource calls, at the destination.
    final_by_path_part = {
        r.get("pathPart"): r["id"] for r in apigw.get_resources(restApiId=api_id)["items"]
    }
    assert final_by_path_part.get("widgets") == resource_id
    assert final_by_path_part.get("gadgets") == other["id"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
