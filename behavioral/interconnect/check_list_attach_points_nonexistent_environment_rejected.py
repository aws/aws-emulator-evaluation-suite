"""list-attach-points-nonexistent-environment-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-attach-points-nonexistent-environment-rejected"
GROUP = "error-semantics"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAttachPoints succeeds for a real Environment (positive control), but for an
    environmentId that does not exist it fails with InterconnectClientException."""
    ic = ctx.client("interconnect")

    envs = ic.list_environments().get("environments", [])
    if not envs:
        raise AssertionError(
            "no accessible Interconnect Environment found in this account/region to use as a "
            "positive control for ListAttachPoints"
        )
    real_env_id = envs[0]["environmentId"]
    ic.list_attach_points(environmentId=real_env_id)

    bad_env_id = ctx.unique_name("sim2real-behav-no-env-")
    code, message = _error(lambda: ic.list_attach_points(environmentId=bad_env_id))
    assert code == "InterconnectClientException", f"got {code!r}"
    expected = f"Unable to process request: This environment model with id {bad_env_id} could not be found"
    assert message == expected, f"got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
