"""launch-template-user-data-base64-round-trip."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "launch-template-user-data-base64-round-trip"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base64-encoded UserData blob set on an EC2 LaunchTemplate version (the kind
    of launch template Auto Scaling groups reference) persists byte-for-byte -- the
    server does not re-encode, strip padding, or otherwise mutate the string."""
    ec2 = ctx.client("ec2")

    script = (
        "#!/bin/bash\n"
        "echo 'sim2real-behav-marker'\n"
        "# special chars: \t\u00e9\u65e5\u672c\u8a9e \n"
    )
    user_data_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": _latest_al2_ami(ctx),
            "InstanceType": "t3.micro",
            "UserData": user_data_b64,
        },
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "sim2real-behav", "Value": lt_name}],
            }
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    version = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id, Versions=["1"])[
        "LaunchTemplateVersions"
    ][0]
    round_tripped = version["LaunchTemplateData"]["UserData"]
    assert round_tripped == user_data_b64, f"UserData mutated: {round_tripped!r} != {user_data_b64!r}"
    decoded = base64.b64decode(round_tripped).decode("utf-8")
    assert decoded == script, f"UserData decodes to a different script: {decoded!r} != {script!r}"


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
