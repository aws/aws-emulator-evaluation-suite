"""concurrent-create-component-same-name-version-contention."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-component-same-name-version-contention"
GROUP = "concurrency"
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
    """Racers creating the same component name and version with distinct client tokens never share a
    build number: every winner gets a distinct build ARN, every loser is refused (ResourceAlreadyExists
    naming the existing build, or BadRequest), and the listed build versions are exactly the winners."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-component-")
    racer_count = 6

    def _racer(_i: int):
        try:
            resp = ib.create_component(
                name=name,
                semanticVersion="1.0.0",
                platform="Linux",
                data=_COMPONENT_DATA,
                clientToken=str(uuid.uuid4()),
                tags={"sim2real": CHECK},
            )
            return ("ok", resp["componentBuildVersionArn"])
        except ClientError as exc:
            err = exc.response["Error"]
            return ("error", (err.get("Code"), err.get("Message", "")))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    successes = [arn for kind, arn in results if kind == "ok"]
    losses = [err for kind, err in results if kind == "error"]
    for arn in successes:
        ctx.on_cleanup(lambda a=arn: ib.delete_component(componentBuildVersionArn=a))

    assert len(successes) >= 1, f"no racer succeeded: {results}"
    exists = {f"The following resource 'Component' already exists: '{arn}'." for arn in successes}
    for code, message in losses:
        # A racer that loses inside the build-number allocation gets BadRequestException instead.
        assert (code == "ResourceAlreadyExistsException" and message in exists) or (
            code == "BadRequestException" and message.startswith("Superfluous identifier provided for ")
        ), f"a losing racer got an unexpected refusal: {results}"
    # every successful racer must have been assigned a distinct build-number ARN
    assert len(set(successes)) == len(successes), f"duplicate ARNs handed out under contention: {successes}"

    # the service's own bookkeeping agrees: no two registered versions share a build number
    build_numbers = [arn.rsplit("/", 1)[-1] for arn in successes]
    assert len(set(build_numbers)) == len(build_numbers), f"duplicate build numbers: {build_numbers}"

    versions = ib.list_component_build_versions(
        componentVersionArn=successes[0].rsplit("/", 1)[0]
    )["componentSummaryList"]
    listed_arns = {v["arn"] for v in versions}
    assert listed_arns == set(successes), (
        f"list_component_build_versions disagrees with what was created: listed={listed_arns} created={set(successes)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
