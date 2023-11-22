# @TEST-DOC: Verifies that only the json-streaming logs exist when configured accordingly.
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT
# @TEST-EXEC: for f in conn files http packet_filter; do test ! -f $f.log; done
# @TEST-EXEC: for f in conn files http packet_filter; do test -f json_streaming_$f.log; done

# Turn off log rotation handling because it only kicks in for some of the files:
redef JSONStreaming::enable_log_rotation = F;

# Turn off default logs:
redef JSONStreaming::disable_default_logs = T;
