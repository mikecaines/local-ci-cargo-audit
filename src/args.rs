use clap::command;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct AppArgs {
	#[arg(short = 'c', long = "config")]
	#[arg(help = "Path to configuration file")]
	pub config_path: PathBuf,

	#[arg(short = 'o', long = "output")]
	#[arg(help = "Path to output file")]
	pub output_path: PathBuf,
}
