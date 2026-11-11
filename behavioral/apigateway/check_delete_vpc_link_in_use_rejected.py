"""delete-vpc-link-in-use-rejected."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vpc-link-in-use-rejected"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _client_error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.
    An unexpected SUCCESS raises, because a target accepting a call real AWS refuses must not
    read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _fake_nlb_arn(ctx):
    """A syntactically-valid NLB ARN that references no real NLB (CreateVpcLink only
    format-checks the ARN synchronously)."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    suffix = uuid.uuid4().hex[:16]
    return (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        f"loadbalancer/net/sim2real-behav-nlb/{suffix}"
    )

def _wait_terminal(ag, vpc_link_id, timeout_s=240):
    """Poll until the VpcLink leaves PENDING (AVAILABLE or FAILED); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ag.get_vpc_link(vpcLinkId=vpc_link_id)["status"]
        if status != "PENDING":
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"VpcLink {vpc_link_id} still PENDING after {timeout_s}s")
        time.sleep(2)

def _wait_gone(ag, vpc_link_id, timeout_s=60):
    """Poll GetVpcLink until it fails; return that (code, message), or raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ag.get_vpc_link(vpcLinkId=vpc_link_id)
        except ClientError as exc:
            error = exc.response["Error"]
            return error["Code"], error.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"VpcLink {vpc_link_id} still readable {timeout_s}s after its delete")
        time.sleep(5)

def _retry_until_ok(fn, timeout_s=60):
    """Retry fn() while it is refused with BadRequestException; raise once the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)

def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVpcLink while still referenced by an Integration must fail (BadRequestException).

    Deleting a VpcLink backing a live Integration must not succeed and break the integration
    (overly-permissive check).
    """
    ag = ctx.client("apigateway")
    target_arn = _fake_nlb_arn(ctx)
    created = ag.create_vpc_link(
        name=ctx.unique_name("sim2real-behav-vpclink-"), targetArns=[target_arn]
    )
    vpc_link_id = created["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ag.delete_vpc_link(vpcLinkId=vpc_link_id)))

    # Let the (fake-NLB-targeted) link leave PENDING first, so a later DeleteVpcLink rejection
    # can only be attributed to the live Integration reference below, not a provisioning race.
    _wait_terminal(ag, vpc_link_id)

    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="proxy")["id"]
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="HTTP_PROXY",
        integrationHttpMethod="GET",
        uri="http://sim2real-behav-backend.example.com/",
        connectionType="VPC_LINK",
        connectionId=vpc_link_id,
    )

    code, message = _client_error(lambda: ag.delete_vpc_link(vpcLinkId=vpc_link_id))
    assert code == "BadRequestException", (
        f"expected BadRequestException deleting a VpcLink still referenced by a live "
        f"Integration, got {code}"
    )
    assert message == (
        f"Cannot delete vpc link. Vpc link '{vpc_link_id}', is referenced in "
        f"[{api_id}:GET:{resource_id}] in format of [RESTApiId:Method:Resource]."
    ), message

    # The rejected delete must not have mutated the VpcLink.
    still_there = ag.get_vpc_link(vpcLinkId=vpc_link_id)
    assert still_there["id"] == vpc_link_id, (
        f"VpcLink {vpc_link_id} should be unaffected by the rejected delete, got {still_there}"
    )

    # Release the reference. Immediately after DeleteIntegration the dependency check can still
    # observe the stale reference for a moment, so retry within a bounded window rather than
    # asserting on the first attempt -- but the identical call must eventually succeed.
    ag.delete_integration(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    _retry_until_ok(lambda: ag.delete_vpc_link(vpcLinkId=vpc_link_id))

    # Deletion proves through: an independent read eventually 404s, and a mutation against the
    # dead id fails the same way.
    get_code, get_message = _wait_gone(ag, vpc_link_id)
    assert get_code == "NotFoundException", (
        f"expected the deleted VpcLink to be gone, GetVpcLink returned {get_code!r}"
    )
    assert get_message == "Invalid Vpc Link identifier specified", get_message
    patch_code, patch_message = _client_error(
        lambda: ag.update_vpc_link(
            vpcLinkId=vpc_link_id,
            patchOperations=[{"op": "replace", "path": "/name", "value": "x"}],
        )
    )
    assert patch_code == "NotFoundException", (
        f"expected a mutation on the deleted VpcLink id to fail, got {patch_code!r}"
    )
    assert patch_message == "Invalid Vpc Link identifier specified", patch_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
