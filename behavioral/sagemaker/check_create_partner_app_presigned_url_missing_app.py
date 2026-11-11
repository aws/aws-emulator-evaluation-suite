"""create-partner-app-presigned-url-missing-app."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-partner-app-presigned-url-missing-app"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePartnerAppPresignedUrl for a partner app ARN that does not exist fails with
    ResourceNotFound 'App entity does not exist.' rather than returning a signed URL."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fake_app_id = uuid.uuid4().hex[:12].upper()
    arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:partner-app/app-{fake_app_id}"

    code, message = _error(lambda: sm.create_partner_app_presigned_url(Arn=arn))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    assert message == "App entity does not exist.", f"unexpected ResourceNotFound message: {message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected ResourceNotFound for a nonexistent partner app, but the call SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
