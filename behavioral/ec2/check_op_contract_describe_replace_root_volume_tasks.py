"""op-contract-describe-replace-root-volume-tasks."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-replace-root-volume-tasks"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeReplaceRootVolumeTasks: success contract returns the
    documented list shape; DryRun=True rejects with DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_replace_root_volume_tasks()
    assert "ReplaceRootVolumeTasks" in resp, f"expected ReplaceRootVolumeTasks key, got keys {list(resp)}"
    assert isinstance(resp["ReplaceRootVolumeTasks"], list), (
        f"expected ReplaceRootVolumeTasks to be a list, got {type(resp['ReplaceRootVolumeTasks'])!r}"
    )

    code, msg = _client_error(lambda: ec2.describe_replace_root_volume_tasks(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
