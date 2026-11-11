"""get-component-policy-without-policy-returns-empty-placeholder."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-component-policy-without-policy-returns-empty-placeholder"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]

_COMPONENT_DATA = """
name: sim2real-test-component
description: minimal test component
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: HelloWorldStep
        action: ExecuteBash
        inputs:
          commands:
            - echo "hello world"
""".strip()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetComponentPolicy on a component with no attached policy does not error: it returns 200
    with an empty JSON object ('{}') as the policy placeholder, rather than synthesizing a real
    policy document or raising ResourceNotFoundException."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-component-")
    arn = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))

    resp = ib.get_component_policy(componentArn=arn)
    assert resp["policy"] == "{}", f"expected empty policy placeholder '{{}}', got {resp['policy']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
