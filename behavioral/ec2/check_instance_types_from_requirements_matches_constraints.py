"""instance-types-from-requirements-matches-constraints."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "instance-types-from-requirements-matches-constraints"
GROUP = "data-plane"
SERVICES = ["ec2"]

_VCPU_MIN, _VCPU_MAX = 2, 4
_MEM_MIN, _MEM_MAX = 4096, 16384


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every instance type returned actually satisfies the supplied vCPU/memory/architecture bounds."""
    ec2 = ctx.client("ec2")

    instance_type_names: list[str] = []
    next_token = None
    while True:
        kwargs = dict(
            ArchitectureTypes=["x86_64"],
            VirtualizationTypes=["hvm"],
            InstanceRequirements={
                "VCpuCount": {"Min": _VCPU_MIN, "Max": _VCPU_MAX},
                "MemoryMiB": {"Min": _MEM_MIN, "Max": _MEM_MAX},
            },
            MaxResults=200,
        )
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ec2.get_instance_types_from_instance_requirements(**kwargs)
        instance_type_names.extend(t["InstanceType"] for t in resp["InstanceTypes"])
        next_token = resp.get("NextToken")
        if not next_token:
            break

    assert instance_type_names, "no instance types matched a broad, easily-satisfiable requirement set"

    details_by_name = {}
    for chunk in _chunks(sorted(set(instance_type_names)), 100):
        resp = ec2.describe_instance_types(InstanceTypes=chunk)
        for info in resp["InstanceTypes"]:
            details_by_name[info["InstanceType"]] = info

    violations = []
    for name in instance_type_names:
        info = details_by_name.get(name)
        assert info is not None, f"DescribeInstanceTypes had no record of returned type {name!r}"
        vcpus = info["VCpuInfo"]["DefaultVCpus"]
        mem_mib = info["MemoryInfo"]["SizeInMiB"]
        architectures = info["ProcessorInfo"]["SupportedArchitectures"]
        virt_types = info.get("SupportedVirtualizationTypes", [])
        if not (_VCPU_MIN <= vcpus <= _VCPU_MAX):
            violations.append(f"{name}: vCPUs={vcpus} outside [{_VCPU_MIN},{_VCPU_MAX}]")
        if not (_MEM_MIN <= mem_mib <= _MEM_MAX):
            violations.append(f"{name}: memory={mem_mib}MiB outside [{_MEM_MIN},{_MEM_MAX}]")
        if "x86_64" not in architectures:
            violations.append(f"{name}: architectures={architectures} missing x86_64")
        if virt_types and "hvm" not in virt_types:
            violations.append(f"{name}: virtualization types={virt_types} missing hvm")

    assert not violations, "instance types violating the supplied constraints: " + "; ".join(violations)


def _chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i : i + size]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
