# @TEST-DOC: Verifies properties of the package's resulting JSON logs. This needs jq.
# @TEST-REQUIRES: jq --version
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT
# Keep only a handful of fields for baselining, this isn't a Zeek internals test.
# @TEST-EXEC: cat json_streaming_conn.log | jq -S '{_path, _write_ts, _system_name, "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", proto, service}' >output.conn
# @TEST-EXEC: btest-diff output.conn
# @TEST-EXEC: cat json_streaming_files.log | jq -S '{_path, _write_ts, _system_name, source, mime_type, filename}' >output.files
# @TEST-EXEC: btest-diff output.files
# @TEST-EXEC: cat json_streaming_http.log | jq -S '{_path, _write_ts, _system_name, method, host, user_agent}' >output.http
# @TEST-EXEC: btest-diff output.http
# @TEST-EXEC: cat json_streaming_packet_filter.log | jq -S '{_path, _write_ts, _system_name, node, filter}' >output.packet_filter
# @TEST-EXEC: btest-diff output.packet_filter

# Set a hostname so we can verify it makes it into the logs:
redef JSONStreaming::system_name = "testsystem";

# Turn off log rotation handling because it only kicks in for some of the files:
redef JSONStreaming::enable_log_rotation = F;
