"""eks-optimized-and-bottlerocket-ami-public-parameters-resolve-to-image-ids."""

from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "eks-optimized-and-bottlerocket-ami-public-parameters-resolve-to-image-ids"
GROUP = "parameter-store"
SERVICES = ["ssm"]

#: A Kubernetes version Amazon EKS still publishes node AMIs for; move it on once it is retired.
_K8S = "1.34"
_PARAMETERS = (
    f"/aws/service/eks/optimized-ami/{_K8S}/amazon-linux-2023/x86_64/standard/recommended/image_id",
    f"/aws/service/bottlerocket/aws-k8s-{_K8S}/x86_64/latest/image_id",
)
_AMI_ID = re.compile(r"ami-[0-9a-f]{17}")


@tags(
    "axis:happy-path",
    "cap:c5",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """EKS optimized and Bottlerocket public image_id parameters resolve to AMI ids.

    Both are read for one supported Kubernetes version, Amazon Linux 2023 and x86_64.
    Reference: https://docs.aws.amazon.com/eks/latest/userguide/retrieve-ami-id.html
    """
    ssm = ctx.client("ssm")

    for name in _PARAMETERS:
        param = ssm.get_parameter(Name=name)["Parameter"]
        assert param["Name"] == name and param["Type"] == "String", (
            f"GetParameter {name} must return that String parameter; got Name={param['Name']!r} "
            f"Type={param['Type']!r}"
        )
        assert _AMI_ID.fullmatch(param["Value"]), (
            f"{name} must resolve to an AMI id ami-<17 hex>; got {param['Value']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
