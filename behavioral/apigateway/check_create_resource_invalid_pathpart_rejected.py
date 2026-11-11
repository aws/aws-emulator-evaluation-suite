"""create-resource-invalid-pathpart-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-invalid-pathpart-rejected"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return the botocore error (code, message, HTTP status). An unexpected success
    raises, so accepted input is reported as accepted rather than as a wrong error code."""
    try:
        result = fn()
    except ClientError as err:
        status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.response["Error"]["Code"], err.response["Error"].get("Message"), status
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource with a '/' in pathPart fails with BadRequestException and creates no resource, while
    a legal pathPart created first succeeds."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)

    # Positive control: a legal pathPart under the same parent succeeds.
    control = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="legal-part")
    assert control.get("pathPart") == "legal-part", (
        f"positive control failed to create pathPart 'legal-part', got {control!r}"
    )

    code, message, status = _error(
        lambda: ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="illegal/slash")
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for a pathPart containing '/', got {code}"
    )
    assert status == 400, f"expected HTTP 400 for a pathPart containing '/', got {status!r}"
    expected_message = "Resource's path part only allow a-zA-Z0-9._-: or a valid greedy path variable and curly braces at the beginning and the end."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    resources = ag.get_resources(restApiId=api_id)["items"]
    assert len(resources) == 2, (
        f"expected only the root and the positive control to exist, got {resources!r}"
    )
    assert not any(r.get("pathPart") == "illegal/slash" for r in resources), (
        f"the rejected pathPart containing '/' was created anyway: {resources!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
