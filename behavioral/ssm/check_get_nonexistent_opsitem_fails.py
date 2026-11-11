"""get-nonexistent-opsitem-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-nonexistent-opsitem-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpsItem returns the check's own OpsItem by id, while a fabricated OpsItemId fails with
    OpsItemNotFoundException and a message that starts "OpsItem not found." and carries the request id."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

    title = ctx.unique_name("sim2real-behav-opsitem-")
    ops_item_id = ssm.create_ops_item(
        Title=title, Description="behavioral fidelity probe", Source="probe.simparity"
    )["OpsItemId"]
    ctx.on_cleanup(lambda: ssm.update_ops_item(OpsItemId=ops_item_id, Status="Resolved"))

    got = ssm.get_ops_item(OpsItemId=ops_item_id)["OpsItem"]
    assert got["Title"] == title, got

    code, message = _error_code(lambda: ssm.get_ops_item(OpsItemId="oi-0123456789ab"))
    assert code == "OpsItemNotFoundException", f"expected OpsItemNotFoundException, got {code!r}"
    # The message embeds a backend request id the check never sees, so match around it.
    assert message.startswith(
        "OpsItem not found. (Service: AmazonSSM; Status Code: 400; "
        "Error Code: OpsItemNotFoundException; Request ID: "
    ) and message.endswith("; Proxy: null)"), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
