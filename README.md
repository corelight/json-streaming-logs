JSON Streaming Logs
-------------------

This packages makes Zeek write out logs in such a way that it makes life easier
for external log shippers such as `filebeats`, `logstash`, and `splunk_forwarder`.

The data is structed as JSON with "extension" fields to indicate the time the
log line was written (`_write_ts`) and log type such as `http` or `conn` in a
field named `_path`.  Files are rotated in the current log directory without
being compressed so that any log shipper has a while to catch up before the
log file is deleted.

Logs are named in such a way that a glob in your log shipper configuration
should be able to easily match all of the logs.  Each log will have a prefix of
`json_streaming_` so that the http log would have the full name of
`json_streaming_http.log`.

Loading this script also doesn't impact any other existing logs that Zeek
outputs.  If you would like to disable other log output from Zeek, you can change
the `JSONStreaming::disable_default_logs` variable to `T`to disable all of the default
logs.  The only potential issue is that your logs will become completely
ephemeral with this change because no logs will be rotated into local storage.

Contact
-------

Please reach out to <info@corelight.com> if you have issues with this script
or if you have thoughts on ways this could better fit into your environment.
