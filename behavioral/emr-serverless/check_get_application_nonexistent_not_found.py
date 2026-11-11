"""get-application-nonexistent-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-application-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApplication on an applicationId that was never created returns ResourceNotFoundException,
    while a real, just-created application remains readable through the identical call."""
    emrs = ctx.client("emr-serverless")

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        tags={"sim2real-check": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))

    # positive control: GetApplication on a real id it just created succeeds
    real = emrs.get_application(applicationId=app_id)["application"]
    assert real["applicationId"] == app_id, (
        f"expected positive control to read back {app_id}, got {real.get('applicationId')}"
    )

    bogus_id = "00000000000nonexist"
    code, message = _error(lambda: emrs.get_application(applicationId=bogus_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created applicationId, got {code}"
    )
    assert message == "Application does not exist", f"unexpected GetApplication not-found message: {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
