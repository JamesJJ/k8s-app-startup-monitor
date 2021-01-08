# Service startup time monitor

*This is a sidecar app to determine latency between K8S pod `Running` state, and service liveness tests actually passing. Timings are exposed as prometheus metrics*

The original purpose is to help identify and quantify service startup delays, and so better determine suitable resource limits or initial monitoring grace time duration.

See also: https://devops.stackexchange.com/questions/8260/kubernetes-metric-or-command-to-show-liveness-delay-time-app-startup-time
