"""register-onprem-instance-missing-iam-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-onprem-instance-missing-iam-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterOnPremisesInstance with neither iamUserArn nor iamSessionArn raises
    IamArnRequiredException, the instance is never registered, and a call carrying a
    real iamUserArn still succeeds."""
    cd = ctx.client("codedeploy")

    name = ctx.unique_name("sim2real-cd-onprem-noarn-")
    error = _client_error(lambda: cd.register_on_premises_instance(instanceName=name))
    assert error == (
        "IamArnRequiredException",
        "The on-premises instance could not be registered because no IAM ARN was included in "
        "the request. Include either an IAM session ARN or IAM user ARN in the request, and then "
        "try again.",
    ), error

    # effect absent: the instance was never registered
    error2 = _client_error(lambda: cd.get_on_premises_instance(instanceName=name))
    assert error2 == (
        "InstanceNotRegisteredException",
        f"The requested host does not exist. Host: {name}",
    ), error2
    assert name not in cd.list_on_premises_instances()["instanceNames"]

    # positive control: same call shape, but with a real IAM user ARN, succeeds
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    good_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user-')}"
    name2 = ctx.unique_name("sim2real-cd-onprem-ok-")
    cd.register_on_premises_instance(instanceName=name2, iamUserArn=good_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=name2))
    info = cd.get_on_premises_instance(instanceName=name2)["instanceInfo"]
    assert info["instanceName"] == name2
    assert info["iamUserArn"] == good_arn


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
