"""create-app-instance-describe-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-app-instance-describe-roundtrip"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAppInstance persists Name/Metadata; DescribeAppInstance reflects them, stamps
    CreatedTimestamp, and — since nothing has been updated yet — reports no LastUpdatedTimestamp."""
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    name = ctx.unique_name("sim2real-chime-ai-")
    token = uuid.uuid4().hex
    metadata = "roundtrip-metadata"

    arn = client.create_app_instance(
        Name=name,
        Metadata=metadata,
        ClientRequestToken=token,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=arn))

    desc = client.describe_app_instance(AppInstanceArn=arn)["AppInstance"]
    assert desc["AppInstanceArn"] == arn, f"expected AppInstanceArn {arn!r}, got {desc['AppInstanceArn']!r}"
    assert desc["Name"] == name, f"expected Name {name!r}, got {desc['Name']!r}"
    assert desc["Metadata"] == metadata, f"expected Metadata {metadata!r}, got {desc['Metadata']!r}"
    assert "CreatedTimestamp" in desc, f"expected CreatedTimestamp in describe response, got keys {sorted(desc)}"
    # Real AWS omits LastUpdatedTimestamp entirely until an actual UpdateAppInstance call (a
    # fresh AppInstanceArn's describe returns only
    # AppInstanceArn/CreatedTimestamp/Metadata/Name). A target that stamps it unconditionally at
    # creation diverges from that contract.
    assert "LastUpdatedTimestamp" not in desc, (
        f"expected no LastUpdatedTimestamp before any update, got {desc.get('LastUpdatedTimestamp')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

