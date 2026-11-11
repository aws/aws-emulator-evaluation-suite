"""describe-account-limits-under-contention-fails."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-account-limits-under-contention-fails"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountLimits during rapid group create/delete churn either returns consistent,
    in-bounds counters or fails with ResourceContention, never another error or a corrupt value."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami_id = _get_amazon_linux_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    created_lock = threading.Lock()
    created_names: list[str] = []
    stop = threading.Event()
    reader_errors: list[Exception] = []
    reader_results: list[dict] = []
    results_lock = threading.Lock()

    def churn_worker(worker_id: int) -> None:
        for i in range(3):
            if stop.is_set():
                return
            name = ctx.unique_name(f"sim2real-behav-churn-{worker_id}-{i}-")
            with created_lock:
                created_names.append(name)
            try:
                autoscaling.create_auto_scaling_group(
                    AutoScalingGroupName=name,
                    LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
                    MinSize=0,
                    MaxSize=0,
                    DesiredCapacity=0,
                    VPCZoneIdentifier=",".join(ctx.network().subnet_ids),
                )
                autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            except ClientError:
                pass  # contention on the write path is not what this check probes
            finally:
                with created_lock:
                    if name in created_names:
                        created_names.remove(name)

    def reader_worker() -> None:
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                resp = autoscaling.describe_account_limits()
                with results_lock:
                    reader_results.append(resp)
            except ClientError as err:
                with results_lock:
                    reader_errors.append(err)
            time.sleep(0.1)

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(churn_worker, w) for w in range(4)]
            futures += [pool.submit(reader_worker) for _ in range(3)]
            for f in futures:
                f.result(timeout=60)
    finally:
        stop.set()
        with created_lock:
            leftovers = list(created_names)
        for name in leftovers:
            try:
                autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            except ClientError:
                pass

    assert reader_results or reader_errors, "no DescribeAccountLimits calls were observed"

    for err in reader_errors:
        code = err.response["Error"]["Code"]
        # The awsQuery wire code of the modeled ResourceContentionFault shape is ResourceContention.
        assert code == "ResourceContention", (
            f"a failing DescribeAccountLimits call under contention must fail with "
            f"exactly ResourceContention, got {code!r}"
        )
        # message varies: contention cannot be produced on demand, so no live message is
        # available to pin; only the code is graded.

    for resp in reader_results:
        num_groups = resp["NumberOfAutoScalingGroups"]
        max_groups = resp["MaxNumberOfAutoScalingGroups"]
        num_lcs = resp["NumberOfLaunchConfigurations"]
        max_lcs = resp["MaxNumberOfLaunchConfigurations"]
        assert 0 <= num_groups <= max_groups, f"corrupted group counters: {num_groups}/{max_groups}"
        assert 0 <= num_lcs <= max_lcs, f"corrupted launch-config counters: {num_lcs}/{max_lcs}"
        assert max_groups > 0, "account limits must be positive"


def _get_amazon_linux_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
