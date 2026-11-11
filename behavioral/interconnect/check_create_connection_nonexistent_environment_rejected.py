"""create-connection-nonexistent-environment-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-connection-nonexistent-environment-rejected"
GROUP = "error-semantics"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnection with a nonexistent environmentId fails with
    InterconnectClientException and its exact message, while GetEnvironment resolves a
    real environment id."""
    ic = ctx.client("interconnect")
    sts = ctx.client("sts")
    remote_account = {"identifier": sts.get_caller_identity()["Account"]}
    attach_point = {"directConnectGateway": "12345678-1234-1234-1234-123456789012"}

    real_env_id = _any_environment_id(ic)

    # positive control: this environmentId is genuinely known to the service
    fetched = ic.get_environment(id=real_env_id)["environment"]
    assert fetched["environmentId"] == real_env_id, (
        f"expected GetEnvironment to resolve {real_env_id!r}, got {fetched.get('environmentId')!r}"
    )

    bad_env_id = ctx.unique_name("sim2real-behav-no-env-")
    bad_code, bad_message = _error(
        lambda: ic.create_connection(
            bandwidth="1Gbps",
            attachPoint=attach_point,
            environmentId=bad_env_id,
            remoteAccount=remote_account,
        )
    )
    assert bad_code == "InterconnectClientException", f"got {bad_code!r}"
    expected = f"Unable to process request: This environment model with id {bad_env_id} could not be found"
    assert bad_message == expected, f"got {bad_message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _any_environment_id(ic):
    envs = ic.list_environments().get("environments", [])
    if not envs:
        raise AssertionError("no Interconnect Environment visible in this account/region")
    return envs[0]["environmentId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
