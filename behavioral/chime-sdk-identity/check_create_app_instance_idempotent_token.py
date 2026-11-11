"""create-app-instance-idempotent-token."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-app-instance-idempotent-token"
GROUP = "idempotency"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Replaying CreateAppInstance with the same ClientRequestToken and identical parameters
    returns the same AppInstanceArn instead of creating a second AppInstance."""
    # chime-sdk-identity's control plane exists only in us-east-1 and eu-central-1 (botocore
    # endpoints.json); us-east-1 is pinned here on real AWS rather than left on ctx.region.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    name = ctx.unique_name("sim2real-chime-ai-")
    token = uuid.uuid4().hex
    metadata = "idempotent-check"
    tag_list = [{"Key": "sim2real-env", "Value": "behavioral"}]

    arn1 = client.create_app_instance(
        Name=name, Metadata=metadata, ClientRequestToken=token, Tags=tag_list
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=arn1))

    arn2 = client.create_app_instance(
        Name=name, Metadata=metadata, ClientRequestToken=token, Tags=tag_list
    )["AppInstanceArn"]

    assert arn2 == arn1, f"replay with the same token minted a new AppInstance: {arn1!r} != {arn2!r}"

    # Only one AppInstance was actually materialized under that identity.
    desc = client.describe_app_instance(AppInstanceArn=arn1)["AppInstance"]
    assert desc["Name"] == name, f"expected Name {name!r}, describe returned {desc['Name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
