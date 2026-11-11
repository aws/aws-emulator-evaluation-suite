"""register-onprem-instance-duplicate-name-blocked."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-onprem-instance-duplicate-name-blocked"
GROUP = "concurrency"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of two concurrent RegisterOnPremisesInstance calls on one instanceName, exactly one wins,
    the other fails with InstanceNameAlreadyRegisteredException, and the record is the winner's."""
    codedeploy = ctx.client("codedeploy")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    instance_name = ctx.unique_name("sim2real-onprem-")
    arn_a = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-usera-')}"
    arn_b = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-userb-')}"
    ctx.on_cleanup(lambda: codedeploy.deregister_on_premises_instance(instanceName=instance_name))

    def _register(arn):
        try:
            codedeploy.register_on_premises_instance(instanceName=instance_name, iamUserArn=arn)
            return ("ok", arn)
        except ClientError as e:
            return (e.response["Error"]["Code"], arn, e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_register, [arn_a, arn_b]))

    ok_results = [r for r in results if r[0] == "ok"]
    failed_results = [r for r in results if r[0] != "ok"]

    assert len(ok_results) == 1, f"expected exactly 1 winner, got {results}"
    assert len(failed_results) == 1, f"expected exactly 1 loser, got {results}"
    loser_code, _, loser_message = failed_results[0]
    assert (loser_code, loser_message) == (
        "InstanceNameAlreadyRegisteredException",
        "Host name has already been registered or recently deregistered",
    ), f"unexpected loser refusal: {failed_results[0]}"

    winner_arn = ok_results[0][1]
    info = codedeploy.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    assert info["iamUserArn"] == winner_arn, "the surviving record was overwritten by the loser"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
