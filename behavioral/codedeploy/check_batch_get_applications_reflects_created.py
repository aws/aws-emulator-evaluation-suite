"""batch-get-applications-reflects-created."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "batch-get-applications-reflects-created"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetApplications, given multiple names in one call, returns every
    created application with its own compute platform and an applicationId
    that agrees with the independent per-application GetApplication call."""
    cd = ctx.client("codedeploy")
    server_name = _create_application(ctx, compute_platform="Server")
    lambda_name = _create_application(ctx, compute_platform="Lambda")

    infos = cd.batch_get_applications(applicationNames=[server_name, lambda_name])["applicationsInfo"]
    by_name = {i["applicationName"]: i for i in infos}
    assert set(by_name) == {server_name, lambda_name}, f"batch mismatch: {sorted(by_name)}"

    for name, platform in ((server_name, "Server"), (lambda_name, "Lambda")):
        batch_entry = by_name[name]
        assert batch_entry["computePlatform"] == platform, batch_entry
        individual = cd.get_application(applicationName=name)["application"]
        assert batch_entry["applicationId"] == individual["applicationId"], (batch_entry, individual)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
