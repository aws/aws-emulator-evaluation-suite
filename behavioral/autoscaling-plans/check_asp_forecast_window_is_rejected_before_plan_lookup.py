"""asp-forecast-window-is-rejected-before-plan-lookup."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-forecast-window-is-rejected-before-plan-lookup"
GROUP = 'predictive-scaling-forecast'
SERVICES = ['autoscaling-plans']

_NS = 'autoscaling'
_DIM = 'autoscaling:autoScalingGroup:DesiredCapacity'
_TYPES = ('LoadForecast', 'CapacityForecast', 'ScheduledActionMinCapacity',
          'ScheduledActionMaxCapacity')


def _expect_validation(fn, want_message, label):
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ValidationException", \
            f"{label}: expected ValidationException, got {code!r} ({message!r})"
        assert status == 400, f"{label}: expected status 400, got {status!r}"
        assert message == want_message, \
            f"{label}: expected message {want_message!r}, got {message!r}"
        return
    raise AssertionError(f"{label}: the call succeeded; expected "
                         f"ValidationException {want_message!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingPlanResourceForecastData checks the time window before looking up the plan: for an
    absent plan a bad window raises ValidationException while a good window returns no datapoints."""
    asp = ctx.client("autoscaling-plans")
    absent = ctx.unique_name("sim2real-behav-asp-absent-")
    now = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0,
                                                   microsecond=0)

    def forecast(start, end, data_type="LoadForecast"):
        return lambda: asp.get_scaling_plan_resource_forecast_data(
            ScalingPlanName=absent, ScalingPlanVersion=1,
            ServiceNamespace=_NS, ResourceId=f"autoScalingGroup/{absent}",
            ScalableDimension=_DIM, ForecastDataType=data_type,
            StartTime=start, EndTime=end)

    # positive control for the ordering: absent plan + valid window -> 200 empty
    ok = forecast(now, now + dt.timedelta(days=1))()
    assert ok["Datapoints"] == [], (
        f"a valid window over the absent plan {absent!r} returned "
        f"{ok['Datapoints']!r}, expected an empty list")

    # the same absent plan, with windows that cannot be served
    _expect_validation(forecast(now, now - dt.timedelta(days=1)),
                       "Start time must be before end time",
                       "end time before start time")
    _expect_validation(forecast(now, now),
                       "Start time must be before end time",
                       "end time equal to start time")
    _expect_validation(forecast(now, now + dt.timedelta(days=10)),
                       "The maximum allowed time range is 7 days",
                       "window wider than the 7-day ceiling")
    _expect_validation(forecast(now - dt.timedelta(days=30),
                                now + dt.timedelta(days=30)),
                       "The maximum allowed time range is 7 days",
                       "window spanning the present but wider than 7 days")

    # the precedence holds for every forecast data type, not just LoadForecast
    for data_type in _TYPES:
        empty = forecast(now, now + dt.timedelta(days=1), data_type)()
        assert empty["Datapoints"] == [], (
            f"{data_type}: a valid window over the absent plan returned "
            f"{empty['Datapoints']!r}, expected an empty list")
        _expect_validation(
            forecast(now, now - dt.timedelta(days=1), data_type),
            "Start time must be before end time",
            f"{data_type} with end time before start time")

    # The 7-day ceiling admits exactly 7 days, and is NOT enforced to the
    # second: 7 days plus a minute is still accepted while
    # 10 days is refused. An emulator comparing (end - start) > 7 days exactly
    # rejects the second case and diverges.
    seven = forecast(now, now + dt.timedelta(days=7))()
    assert seven["Datapoints"] == [], (
        f"a window of exactly 7 days returned {seven['Datapoints']!r}, expected "
        f"an empty list -- the ceiling admits 7 days")
    over = forecast(now, now + dt.timedelta(days=7, minutes=1))()
    assert over["Datapoints"] == [], (
        f"a window of 7 days plus a minute returned {over['Datapoints']!r}; real "
        f"AWS accepts it, so the ceiling is not a strict second-precision "
        f"comparison")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
