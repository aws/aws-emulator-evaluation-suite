"""batch-get-on-premises-instances-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-on-premises-instances-limit-exceeded-rejected"
GROUP = "negative-classes"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetOnPremisesInstances with 101 names is refused with BatchLimitExceededException "BatchGet
    size limit is 100", while 100 unregistered names return an empty instanceInfos list."""
    cd = ctx.client("codedeploy")

    over_limit_names = [ctx.unique_name(f"sim2real-cd-batch-{i}-") for i in range(101)]
    code, message = _error(
        lambda: cd.batch_get_on_premises_instances(instanceNames=over_limit_names)
    )
    assert code == "BatchLimitExceededException", (
        f"expected BatchLimitExceededException for a {len(over_limit_names)}-name "
        f"batch (limit is 100), got {code!r}"
    )
    assert message == "BatchGet size limit is 100", (
        f"expected message 'BatchGet size limit is 100', got {message!r}"
    )

    # positive control: a batch at the 100-name limit is accepted (the
    # call itself succeeds; unregistered names are silently omitted from the
    # response rather than raising, per the documented response shape)
    within_limit_names = over_limit_names[:100]
    resp = cd.batch_get_on_premises_instances(instanceNames=within_limit_names)
    assert resp["instanceInfos"] == [], (
        f"expected no instanceInfos for {len(within_limit_names)} never-registered "
        f"names, got {resp['instanceInfos']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
