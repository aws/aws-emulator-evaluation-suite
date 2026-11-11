"""delete-resource-removes-child-methods."""
from __future__ import annotations

import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-removes-child-methods"
GROUP = 'resources'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _client_error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(
        f"expected this call against the deleted resource to fail, but it SUCCEEDED "
        f"and returned {result!r}"
    )

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _put_basic_method(ag, api_id, resource_id, http_method="GET"):
    """A fully integrated MOCK method (deployable without a real backend)."""
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                  authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                       type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                           statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                                statusCode="200")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteResource, methods that lived on it are no longer retrievable, and the
    dead resourceId also rejects a fresh mutation rather than silently accepting one."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, rest_api_id)
    resource_id = ag.create_resource(
        restApiId=rest_api_id, parentId=root_id, pathPart=f"gone{_unique_token()}"
    )["id"]
    _put_basic_method(ag, rest_api_id, resource_id, "GET")

    ag.delete_resource(restApiId=rest_api_id, resourceId=resource_id)

    code, message = _client_error(
        lambda: ag.get_method(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Resource identifier specified", message

    code, message = _client_error(
        lambda: ag.put_method(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="POST",
            authorizationType="NONE",
        )
    )
    assert code == "NotFoundException", (
        f"expected a fresh PutMethod against the deleted resourceId to be rejected "
        f"NotFoundException, got {code}"
    )
    assert message == "Invalid Resource identifier specified", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
