"""op-contract-modify-verified-access-instance."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-verified-access-instance"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVerifiedAccessInstance updates the Description; bad instance id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-vai-")

    vai_id = ec2.create_verified_access_instance(
        Description="initial",
        TagSpecifications=[{"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=vai_id))

    new_desc = ctx.unique_name("sim2real-vai-desc-")
    resp = ec2.modify_verified_access_instance(VerifiedAccessInstanceId=vai_id, Description=new_desc)
    assert resp["VerifiedAccessInstance"]["Description"] == new_desc, resp["VerifiedAccessInstance"]

    described = ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[vai_id])[
        "VerifiedAccessInstances"
    ][0]
    assert described["Description"] == new_desc, "modification did not persist"

    code, code_msg = _client_error(
        lambda: ec2.modify_verified_access_instance(VerifiedAccessInstanceId="vai-00000000000000000", Description="x")
    )
    assert code == "InvalidVerifiedAccessInstanceId.NotFound", f"unexpected error code: {code}"
    assert code_msg == "The verified-access-instance ID 'vai-00000000000000000' does not exist", code_msg


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
