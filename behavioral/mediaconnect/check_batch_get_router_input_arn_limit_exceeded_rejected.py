"""batch-get-router-input-arn-limit-exceeded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-router-input-arn-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetRouterInput rejects more than 20 Arns with BadRequestException and no
    partial result, while a request for one real router input Arn returns that input."""
    mc = ctx.client("mediaconnect")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    too_many_arns = [
        f"arn:aws:mediaconnect:{region}:{account_id}:routerInput:{i:012x}" for i in range(21)
    ]

    code, message = _client_error(lambda: mc.batch_get_router_input(Arns=too_many_arns))
    assert code == "BadRequestException", (
        f"BatchGetRouterInput with {len(too_many_arns)} Arns (limit 20) must be rejected with "
        f"BadRequestException; got {code!r} / {message!r}"
    )
    expected = (
        "Validation failed:\nToo many ARNs provided. The maximum number of Router Inputs that "
        "can be requested in a single batch is 20."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a real router input, well under the 20-Arn limit
    ni_arn = _create_public_network_interface(ctx, mc)
    input_arn = _create_router_input(ctx, mc, ni_arn)
    resp = mc.batch_get_router_input(Arns=[input_arn])
    assert any(ri["Arn"] == input_arn for ri in resp["RouterInputs"]), (
        f"BatchGetRouterInput([{input_arn!r}]) must return that router input; "
        f"got RouterInputs={resp['RouterInputs']!r}"
    )


# ===== helpers =====
def _create_public_network_interface(ctx, mc) -> str:
    ni_resp = mc.create_router_network_interface(
        Name=ctx.unique_name("sim2real-mc-rni-"),
        Configuration={"Public": {"AllowRules": [{"Cidr": "203.0.113.0/24"}]}},
        Tags={"sim2real:managed": "true"},
    )
    ni_arn = ni_resp["RouterNetworkInterface"]["Arn"]
    ctx.on_cleanup(lambda: _delete_network_interface(mc, ni_arn))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = mc.get_router_network_interface(Arn=ni_arn)["RouterNetworkInterface"]["State"]
        if state == "ACTIVE":
            return ni_arn
        time.sleep(3)
    raise AssertionError("router network interface never reached ACTIVE")


def _create_router_input(ctx, mc, ni_arn: str) -> str:
    resp = mc.create_router_input(
        Name=ctx.unique_name("sim2real-mc-rin-"),
        Configuration={
            "Standard": {
                "NetworkInterfaceArn": ni_arn,
                "Protocol": "RTP",
                "ProtocolConfiguration": {"Rtp": {"Port": 5200}},
            }
        },
        MaximumBitrate=10_000_000,
        RoutingScope="REGIONAL",
        Tier="INPUT_20",
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["RouterInput"]["Arn"]
    ctx.on_cleanup(lambda: _delete_router_input(mc, arn))
    return arn


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: accepting a
    request AWS refuses is reported as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


_GONE = ("NotFoundException", "ResourceNotFoundException")


def _delete_router_input(mc, arn: str) -> None:
    """Wait out CREATING (a router input just created cannot always be deleted immediately)
    before deleting, so the dependent network interface's own delete isn't rejected next."""
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            state = mc.get_router_input(Arn=arn)["RouterInput"]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in _GONE:
                return
            raise
        if state != "CREATING":
            break
        time.sleep(2)
    try:
        mc.delete_router_input(Arn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE:
            raise


def _delete_network_interface(mc, ni_arn: str) -> None:
    """Retry: a network interface just released by a deleted router input can still be
    reported in-use for a few seconds after the input delete call returns. The engine's
    own run_cleanups() swallows a final raise, so there is no need to swallow it here too."""
    deadline = time.monotonic() + 30
    while True:
        try:
            mc.delete_router_network_interface(Arn=ni_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
