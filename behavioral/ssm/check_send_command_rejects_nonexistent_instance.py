"""send-command-rejects-nonexistent-instance."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-command-rejects-nonexistent-instance"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendCommand naming an InstanceId that is not a managed node is refused InvalidInstanceId,
    while a tag-targeted SendCommand matching nothing is accepted and stays listed."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )

    # A tag target matching nothing is accepted (a Command with zero invocations).
    tag_key = "tag:" + ctx.unique_name("nomatch-")
    control = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        Targets=[{"Key": tag_key, "Values": [ctx.unique_name("val-")]}],
        Parameters={"commands": ["echo behavioral-probe"]},
    )
    control_command_id = control["Command"]["CommandId"]
    assert control["Command"]["DocumentName"] == "AWS-RunShellScript", control["Command"]

    code, message = _error_code(
        lambda: ssm.send_command(
            DocumentName="AWS-RunShellScript",
            InstanceIds=["i-0123456789abcdef0"],
            Parameters={"commands": ["echo behavioral-probe"]},
        )
    )
    assert code == "InvalidInstanceId", f"expected InvalidInstanceId, got {code!r}"
    assert message == "Instances not in a valid state for account", message

    listed = ssm.list_commands(CommandId=control_command_id)["Commands"]
    assert len(listed) == 1 and listed[0]["CommandId"] == control_command_id, listed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
