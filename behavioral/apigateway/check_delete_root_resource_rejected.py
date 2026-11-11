"""delete-root-resource-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delete-root-resource-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResource on the root resource ('/') fails with BadRequestException "Root resource cannot be
    deleted" and the root remains, while deleting an ordinary child resource succeeds."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-rootdel-"),
        tags={"sim2real": "delete-root-resource-rejected"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    child_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="child")["id"]
    apigw.delete_resource(restApiId=api_id, resourceId=child_id)
    child_gone_code, child_gone_message = _client_error(
        lambda: apigw.get_resource(restApiId=api_id, resourceId=child_id)
    )
    assert child_gone_code == "NotFoundException", (
        f"expected NotFoundException reading deleted child resource, got {child_gone_code!r}"
    )
    assert child_gone_message == "Invalid Resource identifier specified", child_gone_message

    code, message = _client_error(lambda: apigw.delete_resource(restApiId=api_id, resourceId=root_id))
    assert code == "BadRequestException", f"expected BadRequestException deleting root resource, got {code!r}"
    assert message == "Root resource cannot be deleted", message

    # The root resource must still be readable/intact afterwards.
    root = apigw.get_resource(restApiId=api_id, resourceId=root_id)
    assert root["path"] == "/", root


def _client_error(fn: Any) -> tuple[str, str | None]:
    """Call fn(); return the (code, message) of its botocore error. An unexpected success raises,
    so an accepted call is reported as accepted rather than as a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
