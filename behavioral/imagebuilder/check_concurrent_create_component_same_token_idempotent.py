"""concurrent-create-component-same-token-idempotent."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-component-same-token-idempotent"
GROUP = "concurrency"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N racing CreateComponent calls with the same clientToken+params all collapse to one ARN;
    a racer that arrives while an identical in-flight request is still being processed may see a
    transient ResourceInUseException, but retrying resolves to the same, single ARN."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    token = str(uuid.uuid4())
    doc = (
        f"name: {name}\n"
        "description: concurrency idempotency test\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )
    racer_count = 8

    def _racer(_i: int) -> tuple[str, str]:
        deadline = time.monotonic() + 60.0
        while True:
            try:
                resp = ib.create_component(
                    name=name,
                    semanticVersion="1.0.0",
                    platform="Linux",
                    data=doc,
                    clientToken=token,
                )
                return ("ok", resp["componentBuildVersionArn"])
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    return ("error", f"{code}: {exc.response['Error'].get('Message', '')}")
                time.sleep(2)

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    assert len(results) == racer_count
    errors = [detail for kind, detail in results if kind == "error"]
    assert not errors, f"racer(s) failed instead of collapsing: {errors}"
    arns = [detail for kind, detail in results if kind == "ok"]
    distinct = set(arns)
    assert len(distinct) == 1, f"idempotent create fanned out into distinct resources: {distinct}"

    arn = arns[0]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    # tag after the race resolves to a single ARN, not on the racing call itself: a `tags` kwarg
    # on the shared-clientToken CreateComponent call breaks the idempotent dedupe under
    # concurrency (real AWS returns BadRequestException "Superfluous identifier ... invalid-
    # component/<id>" for some racers).
    ib.tag_resource(resourceArn=arn, tags={"sim2real-check": CHECK})

    versions = ib.list_component_build_versions(componentVersionArn=arn.rsplit("/", 1)[0])["componentSummaryList"]
    assert len(versions) == 1


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
