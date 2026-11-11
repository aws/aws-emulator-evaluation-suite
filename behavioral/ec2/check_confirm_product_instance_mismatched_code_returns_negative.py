"""confirm-product-instance-mismatched-code-returns-negative."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "confirm-product-instance-mismatched-code-returns-negative"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmProductInstance with a well-formed product code the caller holds no subscription to is refused with
    AuthFailure "Not authorised for product code <code>", never answered Return=False, and the instance still
    carries no product codes.
    """
    ec2 = ctx.client("ec2")
    ami_id = _latest_amazon_linux_ami(ec2)
    name = ctx.unique_name("sim2real-confirm-product-")

    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # Positive control: the account and credentials are healthy for EC2 -- the instance
    # launched and reports no product codes of its own (a plain public AMI carries none).
    before = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="productCodes"
    )["ProductCodes"]
    assert before == [], f"expected a fresh AMI-launched instance to carry no product codes, got {before!r}"

    # For a well-formed product code the caller holds no subscription to, ConfirmProductInstance
    # refuses to answer at all, as for any code the caller may not query.
    bogus_product_code = "5F1A2B3C"  # well-formed, not held by the caller
    code, message = _error_detail(
        lambda: ec2.confirm_product_instance(InstanceId=instance_id, ProductCode=bogus_product_code)
    )
    assert code == "AuthFailure", (
        f"expected AuthFailure (not authorised to query this product code), got {code!r} ({message})"
    )
    assert message == f"Not authorised for product code {bogus_product_code}", f"unexpected error message {message!r}"

    # Effect absence: the refused query attached nothing to the instance.
    after = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="productCodes"
    )["ProductCodes"]
    assert after == [], f"expected no product codes after a refused confirm, got {after!r}"


def _latest_amazon_linux_ami(ec2) -> str:
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
        ],
    )
    images = resp["Images"]
    assert images, "no al2023-ami-*-x86_64 AMI found owned by amazon in this region"
    images.sort(key=lambda img: img["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _error_detail(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected ConfirmProductInstance to raise, but it returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
