"""op-contract-deleteVerifiedAccessInstance."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVerifiedAccessInstance"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVerifiedAccessInstance removes the instance; describing it afterwards fails NotFound."""
    ec2 = ctx.client("ec2")

    created = ec2.create_verified_access_instance(
        Description="sim2real behavioral check",
        TagSpecifications=[_tag_spec(ctx, "verified-access-instance", "vai")],
    )
    instance_id = created["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            try:
                ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidVerifiedAccessInstanceId.NotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    described = ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance_id])
    described_id = described["VerifiedAccessInstances"][0]["VerifiedAccessInstanceId"]
    assert described_id == instance_id, f"expected describe to return {instance_id!r}, got {described_id!r}"

    delete_resp = ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id)
    state["deleted"] = True
    deleted_id = delete_resp["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    assert deleted_id == instance_id, f"expected delete response to echo {instance_id!r}, got {deleted_id!r}"

    code, message = _error(lambda: ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance_id]))
    assert code == "InvalidVerifiedAccessInstanceId.NotFound", f"unexpected error describing a deleted instance: {code}: {message}"
    assert message == f"VerifiedAccessInstance {instance_id} does not exist", message

    # distinct error boundary: re-deleting the already-deleted instance is rejected
    code, message = _error(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id))
    assert code == "InvalidVerifiedAccessInstanceId.NotFound", f"unexpected error re-deleting an instance: {code}: {message}"
    assert message == f"The verified-access-instance ID '{instance_id}' does not exist", message


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
