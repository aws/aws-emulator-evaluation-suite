"""get-application-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-application-not-found"
GROUP = "error-semantics"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApplication on a real application succeeds, while a well-formed but nonexistent
    applicationId fails with ResourceNotFoundException."""
    emrs = ctx.client("emr-serverless")

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real": "true"},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))

    # positive control: a real application is readable through the same operation
    real = emrs.get_application(applicationId=app_id)["application"]
    assert real["applicationId"] == app_id, (
        f"expected positive control to read back {app_id!r}, got {real.get('applicationId')!r}"
    )

    bogus_id = "00000000000000000000000000000000"
    code, message = _error(lambda: emrs.get_application(applicationId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
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
