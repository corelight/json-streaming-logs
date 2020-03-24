
module JSONStreaming;

export {
	## If you would like to disable your default logs and only log the
	## "JSON streaming" format of logs set this to `T`.  By default this setting
	## will continue logging your logs in whatever format you specified 
	## and also log them with the "json_streaming_" prefix and all of the 
	## associated settings.
	const JSONStreaming::disable_default_logs = F &redef;

	## The number of extra files that Bro will leave laying around so that
	## any process watching the inode can finish.  The files will be named
	## with the following scheme: `json_streaming_<path>.<num>.log`.  So, the 
	## first conn log would be named: `json_streaming_conn.1.log`.
	const JSONStreaming::extra_files = 4 &redef;

	## A rotation interval specifically for the JSON streaming logs.  This is 
	## set separately since these logs are ephemeral and meant to be
	## immediately carried off to some other storage and search system.
	const JSONStreaming::rotation_interval = 15mins &redef;
}

type JsonStreamingExtension: record {
	## The log stream that this log was written to.
	path:   string &log;
	## Timestamp when the log was written. This is a
	## timestamp as given by most other software.  Any
	## other log-specific fields will still be written.
	write_ts: time   &log;
};

function add_json_streaming_log_extension(path: string): JsonStreamingExtension
	{
	return JsonStreamingExtension($path     = sub(path, /^json_streaming_/, ""),
	                              $write_ts = network_time());
	}

# We get the log suffix just to be safe.
global log_suffix = getenv("BRO_LOG_SUFFIX") == "" ? "log" : getenv("BRO_LOG_SUFFIX");

function rotate_logs(info: Log::RotationInfo): bool
	{
	local i = extra_files-1;
	while ( i > 0 )
		{
		if ( file_size(info$path + "." + cat(i) + "." + log_suffix) >= 0 )
			{
			rename(info$path + "." + cat(i) + "." + log_suffix, 
			       info$path + "." + cat(i+1) + "." + log_suffix);
			}
		--i;
		}
	rename(info$fname, info$path + ".1.log");
	return T;
	}

event zeek_init() &priority=-1000
	{
	for ( stream in Log::active_streams )
		{
		for ( filter_name in Log::get_filter_names(stream) )
			{
			# This is here because we're modifying the list of filters right now...
			if ( /-json-streaming$/ in filter_name )
				next;

			local filt = Log::get_filter(stream, filter_name);

			if ( filter_name == "default" && JSONStreaming::disable_default_logs )
				filt$name = "default";
			else
				filt$name = filter_name + "-json-streaming";

			if ( filt?$path )
				filt$path = "json_streaming_" + filt$path;
			else if ( filt?$path_func ) 
				filt$path = "json_streaming_" + filt$path_func(stream, "", []);
			
			filt$writer = Log::WRITER_ASCII;
			filt$postprocessor = rotate_logs;
			filt$interv = rotation_interval;

			filt$ext_func = add_json_streaming_log_extension;
			filt$ext_prefix = "_";

			# This works around a bug in the base logging script 
			# that sets the default value to an incompatible type
			if ( |filt$config| == 0 )
				filt$config = table_string_of_string();

			filt$config["use_json"] = "T";
			filt$config["json_timestamps"] = "JSON::TS_ISO8601";
			# Ensure compressed logs are disabled.
			filt$config["gzip_level"] = "0";

			local result = Log::add_filter(stream, filt);
			}
		}
	}
