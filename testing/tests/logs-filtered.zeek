# @TEST-DOC: Verifies that Zeek by default writes both the usual logs and the (filtered) json-streaming ones.
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT
# @TEST-EXEC: for f in conn files http packet_filter; do test -f $f.log; done
# @TEST-EXEC: for f in files http; do test -f json_streaming_$f.log; done
# @TEST-EXEC: for f in conn packet_filter; do ! test -f json_streaming_$f.log; done

# Filter the list of files
redef JSONStreaming::enabled_logs = set(HTTP::LOG, Files::LOG);
# Turn off log rotation handling because it only kicks in for some of the files:
redef JSONStreaming::enable_log_rotation = F;
