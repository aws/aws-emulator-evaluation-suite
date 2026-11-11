"""put-integration-without-method-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-integration-without-method-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
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
    """PutIntegration on a resource without a method fails with NotFoundException while it
    succeeds on a sibling resource that has one; once the method is added, the identical call
    succeeds, so the refusal is caused by the missing method."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)

    # ---- positive control: PutIntegration succeeds on a resource that already has a method ----
    control_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="control")["id"]
    ag.put_method(restApiId=api_id, resourceId=control_id, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=control_id, httpMethod="GET", type="MOCK")
    control_got = ag.get_integration(restApiId=api_id, resourceId=control_id, httpMethod="GET")
    assert control_got["type"] == "MOCK", (
        f"positive control: expected the control resource's integration to read back as MOCK, "
        f"got {control_got.get('type')!r}"
    )

    # ---- break: an orphan resource with no method configured yet ----
    orphan_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="orphan")["id"]

    code, message = _error(
        lambda: ag.put_integration(
            restApiId=api_id, resourceId=orphan_id, httpMethod="GET", type="MOCK"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == (
        'Invalid Method identifier specified'
    ), f"unexpected {code} message: {message!r}"

    # ---- effect absent: an independent read confirms no integration was stored ----
    absent_code, absent_code_message = _error(
        lambda: ag.get_integration(restApiId=api_id, resourceId=orphan_id, httpMethod="GET")
    )
    assert absent_code == "NotFoundException", (
        f"expected GetIntegration to also report NotFoundException after the refused "
        f"PutIntegration, got {absent_code!r}"
    )
    assert absent_code_message == (
        'Invalid Integration identifier specified'
    ), f"unexpected {absent_code} message: {absent_code_message!r}"

    # ---- restore: create the method, then retry the IDENTICAL PutIntegration call ----
    ag.put_method(restApiId=api_id, resourceId=orphan_id, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=orphan_id, httpMethod="GET", type="MOCK")
    restored = ag.get_integration(restApiId=api_id, resourceId=orphan_id, httpMethod="GET")
    assert restored["type"] == "MOCK", (
        f"expected the identical PutIntegration to succeed once the method exists, "
        f"got type={restored.get('type')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
