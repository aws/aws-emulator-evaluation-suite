"""get-resource-dashboard-unknown-resource-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-resource-dashboard-unknown-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourceDashboard on a well-formed session ARN for no real session fails
    InvalidRequestException, both under an unknown workgroup and under a real one."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/"
        f"{ctx.unique_name('sim2real-behav-nowg-')}/session/s-{uuid.uuid4().hex[:16]}"
    )
    code, message = _error(lambda: athena.get_resource_dashboard(ResourceARN=bogus_arn))
    assert code == "InvalidRequestException", f"GOT={code!r}"
    assert message == "ResourceARN is not found", f"GOT message={message!r}"

    real_wg = ctx.unique_name("sim2real-behav-dashwg-")
    athena.create_work_group(
        Name=real_wg, Tags=[{"Key": "sim2real", "Value": "get-resource-dashboard-unknown-resource-not-found"}]
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=real_wg))
    got_name = athena.get_work_group(WorkGroup=real_wg)["WorkGroup"]["Name"]
    assert got_name == real_wg, f"expected freshly created workgroup {real_wg!r}, GOT={got_name!r}"

    arn_under_real_wg = (
        f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{real_wg}/session/s-{uuid.uuid4().hex[:16]}"
    )
    code2, message2 = _error(lambda: athena.get_resource_dashboard(ResourceARN=arn_under_real_wg))
    assert code2 == "InvalidRequestException", (
        f"real workgroup + never-issued session id: expected InvalidRequestException, GOT={code2!r}"
    )
    assert message2 == "ResourceARN is not found", (
        f"real workgroup + never-issued session id: GOT message={message2!r}"
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
