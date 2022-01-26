
use std::env;
use std::path::Path;
use std::process::exit;
use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;

use java_properties::read;

pub fn read_config( project_code : &str, var_name : &str ) -> HashMap<String, String> {

    let doka_env = match env::var(var_name) {
        Ok(env) => env,
        Err(e) => {
            eprintln!("💣 Cannot find the DOKA_ENV system variable, {}", e);
            exit(-99);
        },
    };

    let config_path = Path::new(&doka_env).join(project_code).join("config/application.properties");

    // dbg!(&config_path);

    let f = match File::open(&config_path) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("💣 Cannot find the configuration file, e={}", e);
            exit(-89);
        }
    };

    let props = match read(BufReader::new(f)) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("💣 Cannot read the configuration file, e={}", e);
            exit(-79);
        }
    };

    eprintln!("Configuration file : props={:?}", &props);

    props
}