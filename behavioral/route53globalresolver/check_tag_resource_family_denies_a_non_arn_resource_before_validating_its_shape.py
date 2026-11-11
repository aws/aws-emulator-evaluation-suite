"""tag-resource-family-denies-a-non-arn-resource-before-validating-its-shape."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-family-denies-a-non-arn-resource-before-validating-its-shape"
GROUP = "validation-ordering"
SERVICES = ["route53globalresolver"]

_NOT_FOUND_CODE = "GR-ERR00309"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _client(ctx):
    """route53globalresolver serves its control plane only in us-east-2, at an api.aws host
    botocore does not resolve by default; ctx.service_url names that host on real AWS and the
    target's endpoint otherwise."""
    return ctx.client(
        "route53globalresolver",
        region="us-east-2",
        endpoint_url=ctx.service_url("https://route53globalresolver.us-east-2.api.aws"),
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, UntagResource and ListTagsForResource authorize the caller against the
    resourceArn before validating its modeled shape: a string that is not ARN-shaped is
    denied, while a well-formed own-service ARN for an absent resource reaches lookup."""
    client = _client(ctx)
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    not_an_arn = "not-an-arn"
    wrong_service_arn = "arn:aws:s3:::" + ctx.unique_name("sim2real-behav-bucket-")
    missing_id = ctx.unique_name("sim2real-behav-gr-")
    own_service_missing_arn = (
        f"arn:aws:route53globalresolver:us-east-2:{ctx.account}:global-resolver/{missing_id}"
    )

    calls = {
        "TagResource": lambda arn: client.tag_resource(resourceArn=arn, tags={"sim2real": "x"}),
        "UntagResource": lambda arn: client.untag_resource(resourceArn=arn, tagKeys=["sim2real"]),
        "ListTagsForResource": lambda arn: client.list_tags_for_resource(resourceArn=arn),
    }

    for op_name, call in calls.items():
        code, message = _error(lambda call=call: call(not_an_arn))
        assert code == "AccessDeniedException", (
            f"{op_name} on a string that is not ARN-shaped must be denied before shape "
            f"validation runs, got {code}: {message!r}"
        )
        assert message == (
            f"User: {caller_arn} is not authorized to perform: "
            f"route53globalresolver:{op_name} on resource: {not_an_arn}"
        ), f"{op_name}: unexpected message {message!r}"

        code, message = _error(lambda call=call: call(own_service_missing_arn))
        assert code == "ResourceNotFoundException", (
            f"{op_name} on a well-formed own-service ARN for an absent resource must reach "
            f"resource lookup, got {code}: {message!r}"
        )
        assert message == f"[{_NOT_FOUND_CODE}] No GlobalResolver found with the ID: {missing_id}", (
            f"{op_name}: unexpected message {message!r}"
        )

    # TagResource and UntagResource validate the ARN's own shape once it is ARN-shaped but
    # names the wrong service. ListTagsForResource is exercised above only for the other two
    # inputs: on this one its own answer is not a stable code to assert against.
    for op_name in ("TagResource", "UntagResource"):
        code, message = _error(lambda call=calls[op_name]: call(wrong_service_arn))
        assert code == "ValidationException", (
            f"{op_name} on an ARN-shaped value for another service must fail shape validation, "
            f"got {code}: {message!r}"
        )
        assert message == f"Invalid ARN format: {wrong_service_arn}", (
            f"{op_name}: unexpected message {message!r}"
        )

    # Positive control: the client, credentials and us-east-2 control-plane endpoint actually
    # work, so the rejections above are not an artifact of a universally broken call.
    listed = client.list_global_resolvers()
    assert "globalResolvers" in listed, f"ListGlobalResolvers response missing its key: {listed!r}"
    assert isinstance(listed["globalResolvers"], list), (
        f"globalResolvers must be a list, got {listed['globalResolvers']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
