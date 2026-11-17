"""delete-cors-configuration-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cors-configuration-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCorsConfiguration on an ApiId that does not exist fails NotFoundException, while it
    still succeeds as a no-op against a real API that was never given a CORS configuration."""
    agw = ctx.client("apigatewayv2")

    real_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-agwv2-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=real_id))

    bogus_id = "bogus-" + real_id
    code, message = _error(lambda: agw.delete_cors_configuration(ApiId=bogus_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent ApiId, got {code}: {message!r}"
    )
    assert message == f"Invalid API identifier specified {ctx.account}:{bogus_id}", (
        f"expected the exact invalid-API-identifier message for {bogus_id}, got {message!r}"
    )

    # Positive control: the same operation succeeds against a real API with no CORS
    # configuration at all, so the rejection above is about THIS id, not a universal denial.
    agw.delete_cors_configuration(ApiId=real_id)
    got = agw.get_api(ApiId=real_id)
    assert not got.get("CorsConfiguration"), (
        f"expected no CorsConfiguration on an API that never had one, got {got.get('CorsConfiguration')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
