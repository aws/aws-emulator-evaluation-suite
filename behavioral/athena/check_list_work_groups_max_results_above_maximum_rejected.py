"""list-work-groups-max-results-above-maximum-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-work-groups-max-results-above-maximum-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListWorkGroups rejects MaxResults above the documented maximum of 50 with
    InvalidRequestException instead of clamping it, and accepts MaxResults=50."""
    # Client-side parameter validation would otherwise short-circuit this before it ever
    # reaches the wire (MaxResults carries a min:1/max:50 range constraint in the model),
    # so use a client with validation disabled to actually exercise the server-side rejection.
    athena = _unvalidated_client(ctx, "athena")

    wg = ctx.unique_name("sim2real-athena-lwg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg))

    code, message = _error(lambda: athena.list_work_groups(MaxResults=51))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for MaxResults=51 (above the documented max of 50), "
        f"got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 50"
    ), f"unexpected ListWorkGroups message: {message!r}"

    names = set()
    token = None
    while True:
        kwargs = {"MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_work_groups(**kwargs)
        names.update(w["Name"] for w in resp["WorkGroups"])
        token = resp.get("NextToken")
        if not token:
            break
    assert wg in names, f"expected {wg} among ListWorkGroups(MaxResults=50) results, got {sorted(names)}"


def _unvalidated_client(ctx, service: str):
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
