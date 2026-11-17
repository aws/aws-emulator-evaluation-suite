"""delete-access-log-settings-nonexistent-stage-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-access-log-settings-nonexistent-stage-not-found"
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
    """DeleteAccessLogSettings against a StageName that does not exist on the API fails
    NotFoundException, while it still succeeds as a no-op on a real stage that was never
    given access log settings."""
    agw = ctx.client("apigatewayv2")

    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-agwv2-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    stage_name = "sim2real"
    agw.create_stage(ApiId=api_id, StageName=stage_name, Tags=TAGS)

    bogus_stage = "missing-" + ctx.unique_name("stage")
    code, message = _error(
        lambda: agw.delete_access_log_settings(ApiId=api_id, StageName=bogus_stage)
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent StageName, got {code}: {message!r}"
    )
    assert message == "Invalid stage identifier specified", (
        f"expected the exact invalid-stage-identifier message, got {message!r}"
    )

    # Positive control: the same operation succeeds as a no-op against the real stage, which
    # never had access log settings configured, so the rejection above is about THIS stage name.
    agw.delete_access_log_settings(ApiId=api_id, StageName=stage_name)
    got = agw.get_stage(ApiId=api_id, StageName=stage_name)
    assert not got.get("AccessLogSettings"), (
        f"expected no AccessLogSettings on a stage that never had any, got {got.get('AccessLogSettings')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
