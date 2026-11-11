"""op-contract-get-instance-types-from-instance-requirements."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-instance-types-from-instance-requirements"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInstanceTypesFromInstanceRequirements previews matching instance types
    for a set of attribute constraints, honoring the constraints in every result;
    an invalid architecture enum value is rejected."""
    ec2 = ctx.client("ec2")

    vcpu_min, vcpu_max = 1, 2
    mem_min, mem_max = 512, 4096
    resp = ec2.get_instance_types_from_instance_requirements(
        ArchitectureTypes=["x86_64"],
        VirtualizationTypes=["hvm"],
        InstanceRequirements={
            "VCpuCount": {"Min": vcpu_min, "Max": vcpu_max},
            "MemoryMiB": {"Min": mem_min, "Max": mem_max},
        },
    )
    types = _list_field(resp, "InstanceTypeSet", "InstanceTypes")
    assert isinstance(types, list) and len(types) > 0, "expected at least one matching instance type"
    names = []
    for entry in types:
        assert "InstanceType" in entry and entry["InstanceType"], entry
        names.append(entry["InstanceType"])

    # Independent read at a different operation: prove the previewed types actually
    # honor the constraints rather than just naming something non-empty.
    details_by_name = {}
    for chunk in _chunks(sorted(set(names)), 100):
        described = ec2.describe_instance_types(InstanceTypes=chunk)["InstanceTypes"]
        for info in described:
            details_by_name[info["InstanceType"]] = info

    violations = []
    for name in names:
        info = details_by_name.get(name)
        assert info is not None, f"DescribeInstanceTypes had no record of previewed type {name!r}"
        vcpus = info["VCpuInfo"]["DefaultVCpus"]
        mem_mib = info["MemoryInfo"]["SizeInMiB"]
        architectures = info["ProcessorInfo"]["SupportedArchitectures"]
        if not (vcpu_min <= vcpus <= vcpu_max):
            violations.append(f"{name}: vCPUs={vcpus} outside [{vcpu_min},{vcpu_max}]")
        if not (mem_min <= mem_mib <= mem_max):
            violations.append(f"{name}: memory={mem_mib}MiB outside [{mem_min},{mem_max}]")
        if "x86_64" not in architectures:
            violations.append(f"{name}: architectures={architectures} missing x86_64")
    assert not violations, "instance types violating the supplied constraints: " + "; ".join(violations)

    code, message = _error(
        lambda: ec2.get_instance_types_from_instance_requirements(
            ArchitectureTypes=["not-a-real-architecture"],
            VirtualizationTypes=["hvm"],
            InstanceRequirements={
                "VCpuCount": {"Min": 1, "Max": 2},
                "MemoryMiB": {"Min": 512, "Max": 4096},
            },
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == (
        "Request contains an invalid value 'not-a-real-architecture' for ArchitectureTypes. "
        "Valid values: [i386, x86_64, arm64, x86_64_mac, arm64_mac]"
    ), message


def _list_field(resp: dict, *candidates: str) -> list:
    for key in candidates:
        if key in resp:
            return resp[key]
    for key, value in resp.items():
        if key != "ResponseMetadata" and isinstance(value, list):
            return value
    raise AssertionError(f"no list-valued field found in response: {sorted(resp)}")


def _chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
