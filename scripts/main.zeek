
module JSONStreaming;

export {
	## An optional system name for the extension fields if you would
	## like to provide it.
	option JSONStreaming::system_name = "";

	## If you would like to disable your default logs and only log the
	## "JSON streaming" format of logs set this to `T`.  By default this setting
	## will continue logging your logs in whatever format you specified
	## and also log them with the "json_streaming_" prefix and all of the
	## associated settings.
	const JSONStreaming::disable_default_logs = F &redef;

	## If you would like to disable rotation of the "JSON streaming" output log
	## files entirely, set this to `F`.
	const JSONStreaming::enable_log_rotation = T &redef;

	## If rotation is enabled, this is the number of extra files that Zeek will
	## leave laying around so that any process watching the inode can finish.
	## The files will be named with the following scheme: `json_streaming_<path>.<num>.log`.
	## So, the first conn log would be named: `json_streaming_conn.1.log`.
	const JSONStreaming::extra_files: int = 4 &redef;

	## If rotation is enabled, this is the rotation interval specifically for the
	## JSON streaming logs.  This is set separately since these logs are ephemeral
	## and meant to be immediately carried off to some other storage and search system.
	const JSONStreaming::rotation_interval = 15mins &redef;
}

type JsonStreamingExtension: record {
	## The log stream that this log was written to.
	path:   string &log;
	## Optionally log a name for the system this log entry came from.
	system_name: string &log &optional;
	## Timestamp when the log was written. This is a
	## timestamp as given by most other software.  Any
	## other log-specific fields will still be written.
	write_ts: time   &log;
};

function add_json_streaming_log_extension(path: string): JsonStreamingExtension
	{
	local e = JsonStreamingExtension($path     = sub(path, /^json_streaming_/, ""),
	                                 $write_ts = network_time());

	if ( system_name != "" )
		e$system_name = system_name;

	return e;
	}

# We get the log suffix just to be safe.
global log_suffix = getenv("ZEEK_LOG_SUFFIX") == "" ? "log" : getenv("ZEEK_LOG_SUFFIX");

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

	if ( extra_files > 0 )
		{
		rename(info$fname, info$path + ".1.log");
		}
	else
		{
		# If no extra files are desired, just remove this file.
		unlink(info$fname);
		}

	return T;
	}

event zeek_init() &priority=-5
	{
	local new_filters: set[Log::ID, Log::Filter] = set();
	local filt: Log::Filter;

	for ( stream in Log::active_streams )
		{
		for ( filter_name in Log::get_filter_names(stream) )
			{
			# This is here because we're modifying the list of filters right now...
			if ( /-json-streaming$/ in filter_name )
				next;

			filt = Log::get_filter(stream, filter_name);

			if ( JSONStreaming::disable_default_logs && filter_name == "default" )
				filt$name = "default";
			else
				filt$name = filter_name + "-json-streaming";

			if ( filt?$path )
				filt$path = "json_streaming_" + filt$path;
			else if ( filt?$path_func )
				filt$path = "json_streaming_" + filt$path_func(stream, "", []);

			filt$writer = Log::WRITER_ASCII;

			if ( JSONStreaming::enable_log_rotation )
				{
				filt$postprocessor = rotate_logs;
				filt$interv = rotation_interval;
				}

			filt$ext_func = add_json_streaming_log_extension;
			filt$ext_prefix = "_";

			# This works around a bug in Zeek's base logging script
			# that sets the default value to an incompatible type.
			# It only affects Zeek versions 3.0 and older, but we
			# don't have good ways to do version-checking for these,
			# so just leave the fix in place.
			if ( |filt$config| == 0 )
				filt$config = table_string_of_string();

			filt$config["use_json"] = "T";
			filt$config["json_timestamps"] = "JSON::TS_ISO8601";
			# Ensure compressed logs are disabled.
			filt$config["gzip_level"] = "0";

			add new_filters[stream, filt];
			}
		}

	# Add the filters separately to avoid problems with modifying a set/table
	# while it's being iterated over.
	for ( [stream, filt] in new_filters )
		{
		Log::add_filter(stream, filt);
		}
	}
