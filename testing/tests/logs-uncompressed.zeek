# @TEST-DOC: Verifies that the package correctly overrides the compression level.
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT
# @TEST-EXEC: for f in conn files http packet_filter; do test -f $f.log.gz; done
# @TEST-EXEC: for f in conn files http packet_filter; do test -f json_streaming_$f.log; done

# Set a compression level for the logs.
redef LogAscii::gzip_level = 5;

# Turn off log rotation handling because it only kicks in for some of the files:
redef JSONStreaming::enable_log_rotation = F;
