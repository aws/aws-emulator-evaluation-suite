"""untag-resource-nonexistent-resource-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-resource-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource against a well-formed but nonexistent resource ARN is rejected as not found."""
    apigw = ctx.client("apigateway")

    # Well-formed API Gateway resource ARN shape (arn:aws:apigateway:<region>::/restapis/<id>)
    # but the restApiId segment does not correspond to any real REST API.
    bogus_id = "zzzzzzzzzz"
    bogus_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{bogus_id}"
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    not_found_message = f"Invalid API identifier specified {account_id}:{bogus_id}"

    err = _client_error(lambda: apigw.untag_resource(resourceArn=bogus_arn, tagKeys=["Foo"]))
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == not_found_message, (
        f"expected {not_found_message!r}, got {err.get('Message')!r}"
    )

    # (b) effect absent: GetTags on the same nonexistent ARN is consistently not-found too
    # (nothing was mutated on any real resource by the rejected call).
    get_err = _client_error(lambda: apigw.get_tags(resourceArn=bogus_arn))
    assert get_err.get("Code") == "NotFoundException", (
        f"expected NotFoundException, got {get_err.get('Code')!r}"
    )
    assert get_err.get("Message") == not_found_message, (
        f"expected {not_found_message!r} from GetTags, got {get_err.get('Message')!r}"
    )

    # (c) positive control: UntagResource against a real, tagged REST API succeeds.
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"), tags={"Foo": "bar"}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    real_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"
    seeded = apigw.get_tags(resourceArn=real_arn)["tags"]
    assert seeded.get("Foo") == "bar", f"expected seeded tag Foo=bar, got {seeded}"

    apigw.untag_resource(resourceArn=real_arn, tagKeys=["Foo"])
    remaining = apigw.get_tags(resourceArn=real_arn)["tags"]
    assert "Foo" not in remaining, "tag was not actually removed"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
