"""concurrent-validation-isolation."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-validation-isolation"
GROUP = "concurrency"
SERVICES = ["marketplace-catalog"]
ARN_PATTERN = r"^arn:[\w+=/,.@-]+:aws-marketplace:[\w+=/,.@-]*:[0-9]+:[\w+=,.@-]+(/[\w+=,.@-]+)*$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls each get the outcome of their own input: a malformed ARN gets
    ValidationException with its exact message, a well-formed foreign ARN gets AccessDeniedException.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    def bad_case(i):
        arn = f"not-an-arn-{i}"
        code, msg = _error_code(lambda: mp.tag_resource(ResourceArn=arn, Tags=[{"Key": "k", "Value": "v"}]))
        return ("bad", i, code, msg)

    def missing_case(i):
        arn = (
            f"arn:aws:aws-marketplace:us-east-1:111122223333:AWSMarketplace/AmiProduct/"
            f"{ctx.unique_name('sim2real-behav-')}-{i}"
        )
        code, msg = _error_code(lambda: mp.tag_resource(ResourceArn=arn, Tags=[{"Key": "k", "Value": "v"}]))
        return ("missing", i, code, msg)

    # Positive control: the client/account/service is otherwise healthy, so a
    # subsequent all-rejected result set means the isolation under test failed
    # rather than the service being broken end to end.
    control = mp.list_change_sets(Catalog="AWSMarketplace")
    assert "ChangeSetSummaryList" in control, f"service unreachable before concurrency run: {control}"

    tasks = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for i in range(4):
            tasks.append(pool.submit(bad_case, i))
            tasks.append(pool.submit(missing_case, i))
        results = [t.result() for t in tasks]

    for kind, i, code, msg in results:
        if kind == "bad":
            assert code == "ValidationException", f"bad_case[{i}] got {code}"
            assert msg == (
                f"[Requested resource arn 'not-an-arn-{i}' is invalid. It should match with {ARN_PATTERN}.]"
            ), f"bad_case[{i}] got {msg!r}"
        else:
            # message varies: AWS embeds the calling principal's ARN, which the check does not create.
            assert code == "AccessDeniedException", f"missing_case[{i}] got {code}"


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
