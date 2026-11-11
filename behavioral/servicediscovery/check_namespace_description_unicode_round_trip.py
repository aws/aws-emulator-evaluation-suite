"""namespace-description-unicode-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "namespace-description-unicode-round-trip"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode/emoji Description set via Create/UpdatePrivateDnsNamespace round-trips byte-identical through GetNamespace."""
    sd = ctx.client("servicediscovery")
    vpc_id = _create_vpc(ctx)

    ns_name = ctx.unique_name("simparity-sd-") + ".local"
    desc1 = "Iñtërnâtiônàlizætiøn 测试 namespace 🚀🎉 — établissement"

    resp = sd.create_private_dns_namespace(Name=ns_name, Vpc=vpc_id, Description=desc1)
    op = _wait_operation(sd, resp["OperationId"])
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace_best_effort(sd, ns_id))

    got1 = sd.get_namespace(Id=ns_id)["Namespace"]
    assert got1["Description"] == desc1, "initial unicode Description was altered on read-back"

    desc2 = "日本語の説明 ñáéíóú 🎌 — второй набор данных"
    update_resp = sd.update_private_dns_namespace(Id=ns_id, Namespace={"Description": desc2})
    _wait_operation(sd, update_resp["OperationId"])

    got2 = sd.get_namespace(Id=ns_id)["Namespace"]
    assert got2["Description"] == desc2, "updated unicode Description was altered on read-back"


def _create_vpc(ctx):
    ec2 = ctx.client("ec2")
    resp = ec2.create_vpc(
        CidrBlock="10.44.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _wait_operation(sd, operation_id, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        status = op["Status"]
        if status == "SUCCESS":
            return op
        if status == "FAIL":
            raise AssertionError(
                f"operation {operation_id} failed: {op.get('ErrorCode')} {op.get('ErrorMessage')}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"operation {operation_id} stuck in {status} after {timeout_s}s")
        time.sleep(interval_s)


def _delete_namespace_best_effort(sd, namespace_id):
    from botocore.exceptions import ClientError

    try:
        op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
        _wait_operation(sd, op_id, timeout_s=180.0)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NamespaceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
