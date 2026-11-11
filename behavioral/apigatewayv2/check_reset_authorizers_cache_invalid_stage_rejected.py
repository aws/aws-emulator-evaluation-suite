"""reset-authorizers-cache-invalid-stage-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "reset-authorizers-cache-invalid-stage-rejected"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-http"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResetAuthorizersCache against a StageName that does not exist on the
    API is rejected with NotFoundException, the real stage is left untouched,
    and resetting the cache on the real stage still succeeds."""
    apigw = ctx.client("apigatewayv2")

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-http-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    stage_name = "dev"
    before = apigw.create_stage(ApiId=api_id, StageName=stage_name, Tags=TAGS)

    # Break: reset the cache for a stage that does not exist on this API.
    bogus_stage = "does-not-exist-" + ctx.unique_name("x")
    code, message = _client_error(
        lambda: apigw.reset_authorizers_cache(ApiId=api_id, StageName=bogus_stage)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected_message = "Invalid stage identifier specified"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the real stage is unaffected by the failed call.
    after = apigw.get_stage(ApiId=api_id, StageName=stage_name)
    assert after["StageName"] == before["StageName"], (
        f"expected {before['StageName']!r}, got {after['StageName']!r}"
    )
    assert after["CreatedDate"] == before["CreatedDate"], (
        f"expected {before['CreatedDate']!r}, got {after['CreatedDate']!r}"
    )

    # Positive control: resetting the cache on the REAL stage succeeds.
    apigw.reset_authorizers_cache(ApiId=api_id, StageName=stage_name)


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
