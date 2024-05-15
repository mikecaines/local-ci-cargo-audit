use clap::{command, Arg};
use std::error::Error;
use std::path::PathBuf;
use std::str::FromStr;

pub fn get_args() -> Result<AppArgs, Box<dyn Error + Send + Sync + 'static>> {
	let matches = command!()
		.about(
			"A simple tool to run `cargo update` for multiple projects, and create/delete a report file \
			 depending on whether everything is up-to-date or not.")
		.arg(
			Arg::new("config")
				.short('c')
				.long("config")
				.takes_value(true)
				.required(true)
				.help("Path to configuration file"),
		)
		.arg(
			Arg::new("output")
				.short('o')
				.long("output")
				.takes_value(true)
				.required(true)
				.help("Path to output file"),
		)
		.get_matches();

	Ok(AppArgs {
		config_path: PathBuf::from_str(matches.value_of("config").expect("Required by clap"))?,
		output_path: PathBuf::from_str(matches.value_of("output").expect("Required by clap"))?,
	})
}

pub struct AppArgs {
	pub config_path: PathBuf,
	pub output_path: PathBuf,
}
