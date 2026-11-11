"""create-partner-app-presigned-url-app-not-found."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-partner-app-presigned-url-app-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePartnerAppPresignedUrl for a well-formed nonexistent Partner AI App ARN fails with
    ResourceNotFound 'App entity does not exist.'."""
    sm = ctx.client("sagemaker")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:partner-app/app-SIM2REALNOTF"

    code, message = _error(lambda: sm.create_partner_app_presigned_url(Arn=bogus_arn))
    assert code == "ResourceNotFound", f"expected ResourceNotFound for a non-existent partner app ARN, got {code!r}"
    assert message == "App entity does not exist.", f"unexpected ResourceNotFound message: {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected create_partner_app_presigned_url to be rejected for a non-existent app, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
