"""cli-sqs-nonexistent-queue-error."""

from __future__ import annotations

import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sqs-nonexistent-queue-error"

GROUP = "overly-permissive"

SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sending to a non-existent queue via CLI fails with NonExistentQueue, while the
    identical CLI send to a queue that exists succeeds."""
    require_tools("aws")
    # The caller's own account: a foreign account in the queue URL is refused as
    # InvalidAddress before the queue-existence check is reached.
    acct = ctx.client("sts").get_caller_identity()["Account"]
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Positive control: the same CLI send against a queue that exists succeeds.
    ok = _run_shell(ctx, f"aws sqs send-message --queue-url {url} --message-body x", check=False)
    assert ok.returncode == 0, (
        f"expected the CLI send to an existing queue to succeed, got rc={ok.returncode}: "
        f"{ok.stderr[-200:]}"
    )

    proc = _run_shell(
        ctx,
        f"aws sqs send-message --queue-url {sqs.meta.endpoint_url}/{acct}/does-not-exist-{ctx.unique_name('')} --message-body x",
        check=False,
    )
    assert proc.returncode != 0, "Expected failure for non-existent queue"
    assert "(AWS.SimpleQueueService.NonExistentQueue)" in proc.stderr, (
        f"Expected AWS.SimpleQueueService.NonExistentQueue in stderr, got: {proc.stderr[-200:]}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with the run's AWS creds + region in the
    env (via ctx.subprocess_env). Raises on non-zero exit when check=True. Returns CompletedProcess."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
