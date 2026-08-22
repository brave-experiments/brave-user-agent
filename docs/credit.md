# Credit

Ali Shahin Shamsabadi, Brian R. Bondy, and Brendan Eich developed the idea behind this
project: that indirect prompt injection can be made structurally impossible rather than merely
unlikely, by enforcing information-flow labels at every boundary and separating routing from
content so untrusted text cannot redirect an action.

Ali took the idea considerably further, working out the enforcement model in detail and
building the first prototype of it in
[SafeHouse](https://github.com/brave-experiments/safehouse).

Brian masterfully productionized SafeHouse into this repository, which applies that model to a
coding agent.

The model backend is [brave/aichat](https://github.com/brave/aichat). The client-side handling
it builds on comes from [brave/brave-core](https://github.com/brave/brave-core). The dockerized
reproducible build setup is from [bbondy/guardrails](https://github.com/bbondy/guardrails).
