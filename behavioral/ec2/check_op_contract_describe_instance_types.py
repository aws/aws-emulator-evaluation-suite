"""op-contract-describeInstanceTypes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstanceTypes"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceTypes returns detailed specs for t3.micro and honors DryRun
    for its permission-check contract."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_instance_types(InstanceTypes=["t3.micro"])
    types = resp.get("InstanceTypes", [])
    assert len(types) == 1, f"expected exactly one instance type, got {types}"
    info = types[0]
    assert info["InstanceType"] == "t3.micro", f"expected t3.micro, got {info['InstanceType']}"
    assert info["VCpuInfo"]["DefaultVCpus"] == 2, f"expected 2 vCPUs, got {info['VCpuInfo']['DefaultVCpus']}"
    assert info["MemoryInfo"]["SizeInMiB"] == 1024, f"expected 1024 MiB, got {info['MemoryInfo']['SizeInMiB']}"
    assert info["BurstablePerformanceSupported"] is True, (
        f"expected t3.micro to be burstable, got {info['BurstablePerformanceSupported']}"
    )

    code, message = _error(lambda: ec2.describe_instance_types(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
