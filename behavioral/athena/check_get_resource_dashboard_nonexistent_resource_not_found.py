"""get-resource-dashboard-nonexistent-resource-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-resource-dashboard-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourceDashboard on the ARN of a session that does not exist fails InvalidRequestException
    rather than returning a dashboard Url."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    # A well-formed session ARN (workgroup/<name>/session/s-<id>) whose session was never issued.
    fake_session_arn = (
        f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/"
        f"{ctx.unique_name('sim2real-nosession-')}/session/s-{uuid.uuid4().hex[:16]}"
    )

    code, message = _error(lambda: athena.get_resource_dashboard(ResourceARN=fake_session_arn))
    assert code == "InvalidRequestException", (
        f"GetResourceDashboard: expected InvalidRequestException, got {code}"
    )
    assert message == "ResourceARN is not found", (
        f"GetResourceDashboard: unexpected message {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
