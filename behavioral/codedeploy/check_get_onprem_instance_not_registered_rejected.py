"""get-onprem-instance-not-registered-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-onprem-instance-not-registered-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOnPremisesInstance for an instance name that was never registered raises
    InstanceNotRegisteredException, while a real registered instance is returned intact."""
    cd = ctx.client("codedeploy")

    missing_name = ctx.unique_name("sim2real-cd-onprem-missing-")
    code, message = _error(lambda: cd.get_on_premises_instance(instanceName=missing_name))
    assert code == "InstanceNotRegisteredException", (
        f"GetOnPremisesInstance for a never-registered name raised {code!r}, "
        f"expected 'InstanceNotRegisteredException'"
    )
    assert message == f"The requested host does not exist. Host: {missing_name}", message

    # positive control: a really-registered instance is fetched back correctly
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user-')}"
    name = ctx.unique_name("sim2real-cd-onprem-real-")
    cd.register_on_premises_instance(instanceName=name, iamUserArn=arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=name))

    info = cd.get_on_premises_instance(instanceName=name)["instanceInfo"]
    assert info["instanceName"] == name, (
        f"a really-registered instance came back as {info.get('instanceName')!r}, "
        f"expected {name!r}"
    )
    assert info["iamUserArn"] == arn, (
        f"a really-registered instance's iamUserArn came back as {info.get('iamUserArn')!r}, "
        f"expected {arn!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected a ClientError but the call succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
