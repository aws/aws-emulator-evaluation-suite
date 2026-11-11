"""list-applications-reflects-created."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "list-applications-reflects-created"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApplications lists a freshly created application by name. The listing is eventually consistent, so a
    full-pagination sweep is polled to a deadline.
    """
    cd = ctx.client("codedeploy")
    name = _create_application(ctx)

    def _names() -> set[str]:
        acc: set[str] = set()
        for page in cd.get_paginator("list_applications").paginate():
            acc.update(page.get("applications", []))
        return acc

    deadline = time.monotonic() + 30
    names: set[str] = set()
    while time.monotonic() < deadline:
        names = _names()
        if name in names:
            break
        time.sleep(1.0)
    assert name in names, f"{name} not in ListApplications result within 30s: {sorted(names)[:20]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
