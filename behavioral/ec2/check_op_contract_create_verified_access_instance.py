"""op-contract-create-verified-access-instance."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-verified-access-instance"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVerifiedAccessInstance: success creates a regional instance carrying the
    supplied description/tags; DryRun=True is honored (permission-checked, no
    mutation)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vai-")

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error(lambda: ec2.create_verified_access_instance(Description=name, DryRun=True))
    assert code == "DryRunOperation", f"unexpected code: {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    before = ec2.describe_verified_access_instances(
        Filters=[{"Name": "tag:Name", "Values": [name]}]
    )["VerifiedAccessInstances"]
    assert before == [], "DryRun must not create an instance"

    # --- success path ---
    resp = ec2.create_verified_access_instance(
        Description=name,
        TagSpecifications=[{"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance = resp["VerifiedAccessInstance"]
    instance_id = instance["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: _delete_instance(ctx, instance_id))
    assert instance["Description"] == name, instance
    assert instance["VerifiedAccessTrustProviders"] == [], (
        f"a freshly created instance must carry no trust providers, got {instance['VerifiedAccessTrustProviders']!r}"
    )
    assert {"Key": "Name", "Value": name} in instance["Tags"], (
        f"expected Name={name!r} tag in {instance['Tags']!r}"
    )

    fetched = ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance_id])[
        "VerifiedAccessInstances"
    ]
    assert len(fetched) == 1 and fetched[0]["Description"] == name, (
        f"independent describe by id did not reflect the created instance: {fetched!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_instance(ctx, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVerifiedAccessInstanceId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
