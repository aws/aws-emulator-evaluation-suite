"""put-component-policy-nonexistent-component-not-found."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-component-policy-nonexistent-component-not-found"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutComponentPolicy against a componentArn that does not exist is rejected as not found."""
    ib = ctx.client("imagebuilder")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_name = ctx.unique_name("sim2real-ib-nonexistent-")
    bogus_arn = f"arn:aws:imagebuilder:{ctx.region}:{account_id}:component/{bogus_name}/1.0.0/1"

    principal_arn = f"arn:aws:iam::{account_id}:root"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": [principal_arn]},
                "Action": ["imagebuilder:GetComponent"],
                "Resource": [bogus_arn],
            }
        ],
    }
    code, message = _error(lambda: ib.put_component_policy(componentArn=bogus_arn, policy=json.dumps(policy)))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"The following required resource 'Component' cannot be found: '{bogus_arn}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a real component accepts the same policy shape
    component_arn = _create_component(ctx)
    real_policy = json.dumps({**policy, "Statement": [{**policy["Statement"][0], "Resource": [component_arn]}]})
    ib.put_component_policy(componentArn=component_arn, policy=real_policy)
    got = json.loads(ib.get_component_policy(componentArn=component_arn)["policy"])
    assert got["Statement"][0]["Action"] == ["imagebuilder:GetComponent"], (
        f"expected positive control policy to reflect ['imagebuilder:GetComponent'], got {got['Statement'][0]['Action']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a componentArn real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_component(ctx, version: str = "1.0.0", platform: str = "Linux") -> str:
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    doc = (
        f"name: {name}\n"
        "description: test component\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )
    resp = ib.create_component(
        name=name,
        semanticVersion=version,
        platform=platform,
        data=doc,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
