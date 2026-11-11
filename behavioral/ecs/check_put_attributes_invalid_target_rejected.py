"""put-attributes-invalid-target-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "put-attributes-invalid-target-rejected"
GROUP = "representation"
SERVICES = ["ecs"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_attributes_when_visible(ecs, cluster_arn, timeout_s=30.0, interval_s=2.0):
    """ListAttributes on a just-created cluster can see ClusterNotFoundException until the cluster
    propagates; retry (bounded) past that one code."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ecs.list_attributes(cluster=cluster_arn, targetType="container-instance")["attributes"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutAttributes rejects an attribute whose targetId references a container instance that
    does not exist in the cluster (TargetNotFoundException) and does not persist it, regardless
    of whether any real container instance is registered in the cluster at all."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-behav-ecs-badtarget-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # A syntactically well-formed container-instance ARN in OUR account/cluster, but one that was
    # never registered by RegisterContainerInstance -- ECS must resolve non-existence for this
    # targetId, not merely reject the shape of the ARN.
    bogus_ci_id = str(uuid.uuid4())
    bogus_ci_arn = f"{cluster_arn.replace(':cluster/', ':container-instance/')}/{bogus_ci_id}"
    expected_message = f"Container instance {bogus_ci_id} not found."
    bogus_attr_name = ctx.unique_name("sim2real-behav-ecs-attr-bogus-")

    code, message = _error(
        lambda: ecs.put_attributes(
            cluster=cluster_arn,
            attributes=[{"name": bogus_attr_name, "value": "x", "targetId": bogus_ci_arn}],
        )
    )
    assert code == "TargetNotFoundException", f"expected TargetNotFoundException, got {code!r}"
    assert message == expected_message, message

    attrs_after = _list_attributes_when_visible(ecs, cluster_arn)
    names_after = {a["name"] for a in attrs_after}
    assert bogus_attr_name not in names_after, "attribute for a nonexistent target was persisted anyway"

    # Same call shape with a well-formed value on the same bogus target still fails the same way
    # (the rejection is about target existence, not about the attribute's value/name content).
    bogus_attr_name2 = ctx.unique_name("sim2real-behav-ecs-attr-bogus2-")
    code2, message2 = _error(
        lambda: ecs.put_attributes(
            cluster=cluster_arn,
            attributes=[{"name": bogus_attr_name2, "targetId": bogus_ci_arn}],
        )
    )
    assert code2 == "TargetNotFoundException", f"expected TargetNotFoundException, got {code2!r}"
    assert message2 == expected_message, message2

    attrs_after2 = _list_attributes_when_visible(ecs, cluster_arn)
    names_after2 = {a["name"] for a in attrs_after2}
    assert bogus_attr_name2 not in names_after2, "attribute for a nonexistent target was persisted anyway"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
