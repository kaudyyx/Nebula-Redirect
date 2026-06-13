#pragma once
#include "ue.h"

constexpr bool Console = false;
constexpr StarfallURLSet URLSet = Default;
constexpr inline FString Backend = L"http://187.77.254.242:5555";
constexpr bool bHasPushWidget = false;

constexpr bool UseBackendParam = false;
constexpr bool ManualMapping = false;
constexpr bool FixMemLeak = true;

// Enable Edit-on-Release. Activate in-game with -eor launch arg.
constexpr bool EnableEOR = true;

// Enable Disable Pre-Edit. Activate in-game with -edp launch arg.
constexpr bool EnableEDP = true;