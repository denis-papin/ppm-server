#![feature(proc_macro_hygiene, decl_macro)]

use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::process::exit;
use std::fs::{File};
use std::io::Write;
use std::{fs, io};
use std::sync::RwLock;
use serde_derive::*;

use log::*;
use rocket::*;
use rocket::request::FromRequest;
use rocket::{Request, request};

use rocket_okapi::{JsonSchema};
use rocket_contrib::json::Json;
use rocket_contrib::serve::StaticFiles;

mod conf_reader;
mod dk_crypto;
mod dk_crypto_error;
mod all_tests;

use conf_reader::*;
use dk_crypto_error::DkCryptoError;
use dk_crypto::{DkEncrypt};
use lazy_static::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use chrono::serde::ts_milliseconds;
use rocket::http::{RawStr, ContentType, Status, Method};

//
// PROPERTIES must be locked when on write, but not locked on read actions
// It contains a double map { 0 : { "server.port" : 30040, "app.secret-folder" : "/secret", .... },... }
// where only the map[0] is used in our case.
//
lazy_static! {
    #[derive(Debug)]
    static ref PROPERTIES : RwLock<HashMap<u32, &'static mut HashMap<String,String>> > = RwLock::new(
        {
            let mut m = HashMap::new();
            let props : HashMap<String,String> = HashMap::new();
            m.insert(0, Box::leak(Box::new( props )));
            m
        });
}

#[derive(Serialize)]
struct TemplateContext {
    message: String,
}

#[derive(Serialize)]
struct CssTemplateContext {
    size: u8,
    font_family: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenId(String);

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct LoginRequest {
    user: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct LoginReply {
    token: String,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct AddKeyRequest {
    title: String,
    url: Option<String>,
    #[serde(rename = "username")]
    login: String,
    pass: String,
    notes: String,
}

type SearchReply = Vec<EntryReply>;
type HistoryReply = HashMap<String, Vec<EntryReply>>;

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct EntryReply {
    uuid: String,
    order: u64,
    title: String,
    #[serde(rename = "username")]
    login : String,
    encrypted_pass: String,
    url : Option<String>,
    notes: Option<String>,
    active: bool,
    timestamp: String,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct AddKeyReply {
    success: bool,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct ClearTextReply {
    clear_text: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Secret {
    transactions: Vec<BusinessTransaction>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct BusinessTransaction {
    uuid: String,
    order: u64,
    title : String,
    url : Option<String>,
    #[serde(rename = "username")]
    login : String,
    #[serde(rename = "cipheredPassword")]
    ciphered_password: String,
    notes: Option<String>,
    enabled: String,
    #[serde(with = "ts_milliseconds")]
    timestamp: DateTime<Utc>,
}

#[derive(Debug)]
pub struct CORS;

impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response
        }
    }

    fn on_response(&self, request: &Request, response: &mut Response) {
        info!("On Response [{}]", &request );
        info!("On Response [{}]", &response.status() );

        let _ = response.status();
        // dbg!(&s);

        if request.method() == Method::Options {
            response.set_status(Status::Ok);
        }

        // TODO : response.adjoin_header(ContentType::JSON );
        response.adjoin_raw_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PATCH, DELETE");
        response.adjoin_raw_header("Access-Control-Allow-Origin", "*");
        response.adjoin_raw_header("Access-Control-Allow-Credentials", "true");
        response.adjoin_raw_header("Access-Control-Allow-Headers", "*");
    }
}

use rocket::config::Environment;
use rs_uuid::iso::uuid_v4;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::response::content::{Css, Html, JavaScript};
use rocket::response::Responder;
use rocket_contrib::templates::{handlebars, Template};


///
/// ✨  Main component...
///
// Fonction pour gérer la page d'accueil
#[get("/index")]
fn index() -> Template {
    // Création des données à afficher dans le template
    let mut context = HashMap::new();
    context.insert("title", "Page d'accueil");
    context.insert("message", "Bienvenue sur notre site web!");

    // Rendu du template avec les données
    Template::render("index", &context)
}

#[get("/search_page")]
fn search_page() -> Template {
    let mut context = HashMap::new();
    context.insert("title", "Page d'accueil");
    context.insert("message", "Bienvenue sur notre site web!");

    Template::render("search", &context)
}

#[get("/input_page")]
fn input_page() -> Template {
    let mut context = HashMap::new();
    context.insert("title", "Page d'accueil");
    context.insert("message", "Bienvenue sur notre site web!");

    Template::render("input", &context)
}

#[get("/resort_info")]
fn resort_info() -> Template {
    // Création des données à afficher dans le template
    let mut context = HashMap::new();
    context.insert("componentName", "resort_info");
    context.insert("address", "35, rue du grand canyon");
    // Rendu du template avec les données
    Template::render("resort_info", &context)
}

#[get("/info_bar")]
fn info_bar() -> Template {
    // Création des données à afficher dans le template
    let mut context = HashMap::new();
    context.insert("componentName", "info_bar");
    context.insert("address", "35, rue du grand canyon");
    // Rendu du template avec les données
    Template::render("info_bar", &context)
}

#[get("/decrypt/<encrypted_text>")]
fn decrypt_key(encrypted_text: &RawStr, token: TokenId) -> Json<ClearTextReply> {
    let master_key = get_prop_value(&token.0);
    match DkEncrypt::decrypt_str(&encrypted_text, &master_key) {
        Ok(clear_key) =>  Json(ClearTextReply { clear_text: clear_key }),
        Err(_) => Json(ClearTextReply { clear_text: "".to_string()}),
    }
}

#[get("/history")]
fn history(token: TokenId) -> Json<HistoryReply> {
    info!("🚀 Start key api, token_id=[{:?}]", &token);

    let (_, username) = parse_token(&token.0);
    let master_key = get_prop_value(&token.0);

    let transactions_result = read_secret_file(&username, &master_key);

    // List of customer keys to return.
    let mut trans_map : HistoryReply = HashMap::new();
    match transactions_result {
        Ok(secret) => {

            for t in secret.transactions {
                let key = EntryReply {
                    uuid: t.uuid,
                    order: t.order,
                    title: t.title,
                    login : t.login,
                    url : t.url,
                    encrypted_pass: t.ciphered_password,
                    notes: t.notes,
                    active: t.enabled == "true",
                    timestamp: t.timestamp.to_string(),
                };

                let new_title = format!("{}:{}", &key.title, &key.login);
                match trans_map.get_mut(&new_title ) {
                    None => {
                        let new_trans = vec![key];
                        let _ = &trans_map.insert(new_title, new_trans);
                    }
                    Some( transactions) => {
                        transactions.push(key);
                    }
                }
            }
        }
        Err(e) => {
            eprint!("{:?}", e);
            // TODO manage the error
        }
    }

    info!("🏁 End key api, token=[{:?}]", &token);
    Json(trans_map)
}

/// An example of how to generate a js structure with some dynamic data in it
#[get("/data.js")]
fn script() -> JavaScript<String> {
    let context = TemplateContext {
        message: String::from("Hello, world!"),
    };
    let handlebars = handlebars::Handlebars::new();
    let template_str = include_str!("data/local_data.js");
    let js_code = handlebars.render_template(template_str, &context).unwrap();
    JavaScript(js_code)
}

#[get("/style.css")]
fn style() -> Css<String> {
    let context = CssTemplateContext {
        size: 2,
        font_family: "Helvetica Neue,Helvetica,Arial,sans-serif".to_string(),
    };
    //let js_code = generate_js("style.css", &context);
    let handlebars = handlebars::Handlebars::new();
    let template_str = include_str!("dyn_css/style.css");
    let js_code = handlebars.render_template(template_str, &context).unwrap();
    Css(js_code)
}

fn filter_most_recent_transactions(secret : &'_ Secret) -> Vec<&'_ BusinessTransaction> {
    // keep a ref on the most recent (title, login)
    let mut most_recent : HashMap<(&'_ String, &'_ String), &'_ BusinessTransaction> = HashMap::new();

    for transaction in &secret.transactions {
        let op_search = most_recent.get(&(&transaction.title, &transaction.login));
        match op_search {
            None => {
                most_recent.insert((&transaction.title, &transaction.login), transaction);
            }
            Some(t) => {
                if t.timestamp.lt(&transaction.timestamp) {
                    most_recent.insert((&transaction.title, &transaction.login), transaction);
                }
            }
        }
    }

    // Extract the list of business transactions from the map into a vec
    let mut eligible : Vec<&'_ BusinessTransaction> = vec![];

    for (_,v) in most_recent {
        eligible.push(v);
    }

    eligible
}


///
///"title": "Krypton",
///"username": "kara",
///"url": "https://krypton.com/kara_zorel",
///"notes": "toto@gmail.com",
///
#[get("/search?<chars>")]
fn search(chars : Option<&RawStr>, token: TokenId) -> Json<SearchReply> {

    info!("🚀 Start search, token_id=[{:?}]", &token);

    let to_be_searched : String = match chars {
        None => {
            "".to_string()
        }
        Some(c) => {
            c.to_string().to_lowercase()
        }
    };

    debug!("chars [{}]", &to_be_searched);

    let (_, username) = parse_token(&token.0);
    let master_key = get_prop_value(&token.0);
    let transactions_result = read_secret_file(&username, &master_key);

    // List of entries to return.

    let mut replies: SearchReply = vec![];
    match transactions_result {
        Ok(secret) => {

            // Search only among the most recent entries
            let recent_transactions = filter_most_recent_transactions(&secret);
            for t in recent_transactions {

                let lower_url = t.url.as_ref().unwrap_or(&"".to_string()).to_lowercase();
                let lower_notes = t.notes.as_ref().unwrap_or(&"".to_string()).to_lowercase();

                if t.title.to_lowercase().contains(&to_be_searched)
                    || t.login.to_lowercase().contains(&to_be_searched)
                    || lower_url.contains(&to_be_searched)
                    || lower_notes.contains(&to_be_searched)
                {
                    let entry = EntryReply {
                        uuid: (&t.uuid).to_string(),
                        order: t.order,
                        title: (&t.title).to_string(),
                        login: (&t.login).to_string(),
                        url: (&t.url).clone(),
                        encrypted_pass: (&t.ciphered_password).to_string(),
                        notes: (&t.notes).clone(),
                        active: t.enabled == "true",
                        timestamp: t.timestamp.to_string(),
                    };

                    let _ = &replies.push(entry);
                }
            }
        }
        Err(e) => {
            eprint!("{:?}", e);
            // TODO manage errors
        }
    }

    info!("🏁 End search, token=[{:?}]", &token);
    Json(replies)
}


#[get("/transaction")]
fn transaction(token: TokenId) -> Json<Secret> {
    info!("🚀 Start transaction, token_id=[{:?}]", &token);

    let (_, username) = parse_token(&token.0);
    let master_key = get_prop_value(&token.0);

    let transactions_result = read_secret_file(&username, &master_key);

    // List of entry keys to return.
    let ret = match transactions_result {
        Ok(secret) => {
            Json(secret)
        }
        Err(e) => {
            eprint!("{:?}", e);
            // TODO
            Json(Secret{transactions: vec![]})
        }
    };
    info!("🏁 End transaction, token=[{:?}]", &token);
    ret
}


impl<'a, 'r> FromRequest<'a, 'r> for TokenId {
    type Error = ();
    fn from_request(my_request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let map = my_request.headers();
        let token = map.get_one("token_id").unwrap();
        request::Outcome::Success(TokenId(token.to_string()))
    }
}

fn create_token(username : &str) -> String {
    format!("{}:{}", uuid_v4(), username)
}

fn parse_token(token_str : &str) -> (String, String) {
    let parts = token_str.split(":").collect::<Vec<&str>>();
    (parts.get(0).unwrap().to_string(), parts.get(1).unwrap().to_string())
}

/// ppm setup -u denis -p "my password"
/// Create an empty file with the username, perform the login process
#[post("/setup", format = "application/json", data = "<request>")]
fn setup(request: Json<LoginRequest>) -> Json<LoginReply> {

    // Check if the user's file already exists

    // Login
    let master_key = DkEncrypt::hash_with_salt(&request.password);
    // dbg!(&master_key);
    let token_str = create_token(&request.user);
    set_prop_value(token_str.as_ref(), &master_key);

    // Create the encrypted user's file
    let secret_folder = get_secret_folder();

    let secret = Secret { transactions: vec![] };
    let res_storage = store_to_file(&secret, &secret_folder, &request.user, &master_key);

    // TODO handle error code and factorize
    match res_storage {
        Ok(_) => {
            let lr = LoginReply {
                token: token_str
            };

            Json(lr)
        }
        Err(_) => {
            let lr = LoginReply {
                token: "ERROR".to_string()
            };
            Json(lr)
        }
    }
}

/// Get the credential in parameters and store the generated master key
/// in the global properties
/// ppm login -u denis -p "my password"
#[post("/login", format = "application/json", data = "<request>")]
fn login(request: Json<LoginRequest>) -> Json<LoginReply> {

    dbg!(&request);

    // We use a constant salt here, and it's good because we need the same hash all the time
    let master_key = DkEncrypt::hash_with_salt(&request.password);

    // dbg!(&master_key);

    let token_str = create_token(&request.user);
    set_prop_value(token_str.as_ref(), &master_key);
    // dbg!(get_prop_value(&token_str));

    // Try to decrypt the file to test the password hash
    let res_secret_result = read_secret_file(&request.user, &master_key);

    let lr = match res_secret_result {
        Ok(_) => {
            let lr = LoginReply {
                token: token_str
            };

            lr
        }
        Err(_) => {
            let lr = LoginReply {
                token: "ERROR".to_string()
            };

            lr
        }
    };

    Json(lr)
}

#[post("/login/text", format = "text/plain", data = "<request>")]
fn login_text(request: Json<LoginRequest>) -> Json<LoginReply> {
    // We use a constant salt here, and it's good because we need the same hash all the time
    let master_key = DkEncrypt::hash_with_salt(&request.password);

    let token_str = create_token(&request.user);
    set_prop_value(token_str.as_ref(), &master_key);

    // Try to decrypt the file to test the password hash
    let res_secret_result = read_secret_file(&request.user, &master_key);

    match res_secret_result {
        Ok(_) => {
            let lr = LoginReply {
                token: token_str
            };

            Json(lr)
        }
        Err(_) => {
            let lr = LoginReply {
                token: "ERROR".to_string()
            };

            Json(lr)
        }
    }
}

///
/// TODO THE TRACE ID / SESSION ID should be in the header
///
/// ppm add --title  "Gmail"  --user "deniz@gmail.com" --password "my funky pass"  --url "https://gmail.com"  --note "Always Https"  [--update]
#[post("/add_key", format = "application/json", data = "<request>")]
fn add_key(request: Json<AddKeyRequest>, token: TokenId) -> Json<AddKeyReply> {

    use rs_uuid::iso::uuid_v4;

    let (_, username) = parse_token(&token.0);
    let master_key = get_prop_value(&token.0);
    let pass_phrase = request.pass.as_str();

    info!("🚀 Start add_key api, token_id={}", &token.0);

    // The pass phrase is not very important, it can be very long.
    // The significant password is the "key" which is the HASH(pass_phrase)
    // Then we encrypt the customer key to make sure it's protected.

    let enc_password = DkEncrypt::encrypt_str(pass_phrase, &master_key);

    // TODO
    //       If the file does not exist, the system crashes
    //       Create a dummy Config object instead.
    let secret_result = read_secret_file(&username, &master_key);

    let entry_count_for_target = match &secret_result {
        Ok(secret) =>   count_entry_for_target(secret, &request.title),
        Err(_) => 0,
    };

    let transaction = BusinessTransaction {
        uuid: uuid_v4(),
        order: entry_count_for_target+1,
        title : request.title.clone(),
        url : request.url.clone(),
        login : request.login.clone(),
        ciphered_password: enc_password,
        notes: Some(request.notes.clone()),
        enabled: "true".to_string(),
        timestamp: Utc::now(),
    };

    info!("Add the key in the transaction : token_id={}, transaction={:?}", &token.0, &transaction);

    // dbg!(&secret_result);

    let success;
    match secret_result {
        Ok(mut secret) => {

            secret.transactions.push(transaction);
            let r_store = store_to_file(&secret, get_secret_folder().as_str(),
                                        &username, &master_key);
            match r_store {
                Ok(_) => {
                    info!("😎 Customer file successfully copied");
                    success = true;
                }
                Err(e) => {
                    error!("💣 Customer file storage failed e={:?}", e);
                    success = false;
                }
            }
        }
        Err(e) => {
            eprint!("{:?}", e);
            // TODO
            success = false;
        }
    }

    if success {
        info!("😎 Customer key added with success");
    }

    let ret = AddKeyReply {
        success
    };
    info!("🏁 End dd_key, token_id = {}, success={}", &token.0, success);
    Json(ret)
}

///
///
///
fn count_entry_for_target(secret: &Secret, customer: &str ) -> u64 {
    let mut count: u64 = 0;
    for t in &secret.transactions {
        if t.title == customer {
            count = count + 1;
        }
    }
    return count;
}

///
/// TODO check if the username is compatible with a filename
/// Build the secret file name : secret_folder + <username> + ".crypt"
/// Username is stored in the token : base64(token = uuid + "_" + <username>)
///
fn store_to_file(secret: &Secret, secret_folder: &str, username : &str, master_key : &str) -> io::Result<u64> {

    // Archive the original customer file into customer_archive_2020_05_22.enc

    let now: DateTime<Utc> = Utc::now();
    let current_date = now.format("%Y_%m_%d_%H_%M_%S").to_string();

    let str = get_secret_file_name(&username);
    let current_fullpath = Path::new(&str);
    let target_filename = format!( "{}_{}.crypt", &username, &current_date.as_str());
    let target_fullpath = Path::new(secret_folder).join(target_filename);

    info!("Want to copy the secret file to target=[{}]", target_fullpath.as_path().to_str().unwrap());

    let copy;
    if current_fullpath.exists() {
        copy = fs::copy(&current_fullpath, &target_fullpath)?;
        info!("Copy done");
    } else {
        copy = 0;
        info!("The file does not exists");
    }

    // Transform the transactions into json
    let json_transactions = serde_json::to_string(&secret)?;

    // Encrypt the final json string
    let b = &json_transactions.into_bytes();
    let enc_json_transactions = DkEncrypt::encrypt_vec(&b, master_key).unwrap_or(vec![]);


    // Store the encrypted json into the customer.enc file.
    let mut f = File::create(&current_fullpath).expect("💣 Customer file should be here !!");
    let _r = f.write_all(&enc_json_transactions[..]);

    Ok(copy)
}


///
/// Set properties[0] with the configuration file values
///
fn set_props(props : HashMap<String, String>) {
    let mut w = PROPERTIES.write().unwrap();
    let item = w.get_mut(&0).unwrap();
    *item = Box::leak(Box::new(props ));
}

///
/// Build the secret file name from the username
///
fn get_secret_file_name(username : &str) -> String {
    let folder = get_secret_folder();
    let current_filename = format!("{}.crypt", &username);
    let path = Path::new(&folder).join(current_filename);
    path.into_os_string().into_string().unwrap()
}

///
/// Get the secret folder name
///
fn get_secret_folder() -> String {
    let folder = get_prop_value("app.secret-folder");
    folder
}

///
/// Get prop value
///
fn get_prop_value(prop_name : &str) -> String {
    // https://doc.rust-lang.org/std/sync/struct.RwLock.html
    let s = PROPERTIES.read().unwrap().deref().get(&0).unwrap().deref()
        .get(prop_name).unwrap().to_owned();

    s
}

///
/// Change an entry in the properties
///
fn set_prop_value(prop_name : &str, value : &str ) -> () {

    info!("Define property [{prop_name}], value : [{value}]");

    if let Ok(write_guard) = PROPERTIES.write().as_mut() {
        // the returned write_guard implements `Deref` giving us easy access to the target value
        let map = write_guard.deref_mut();
        if  let Some( item ) = map.get_mut(&0) {
            item.insert(prop_name.to_string(), value.to_string());
        }
    }
    ()
}


///
/// Read the entire secret file and place the content in a Secret structure
///
fn read_secret_file(username : &str, master_key : &str) -> Result<Secret, DkCryptoError> {
    let current_fullpath = get_secret_file_name(username);

    // Check if the customer file exists
    if ! Path::new(&current_fullpath).exists() {
        // create a simple secret
        let secret : Secret = Secret { transactions: vec![] };
        return Ok(secret);
    }

    info!("Read the crypted customer file : {}", &current_fullpath);

    // Read the customer file
    let json_transactions_result = DkEncrypt::decrypt_file(current_fullpath.as_str(), &master_key);

    // The program stops for some reason here !!!
    let json_transactions: String;
    match json_transactions_result {
        Ok(v) => {
            json_transactions = v;
        }
        Err(_e) => {
            json_transactions = "".to_string();
            // TODO ...
        }
    }


    let r_transactions: Result<Secret, _> = serde_json::from_str(json_transactions.as_str());

    let r_secret: Result<Secret, DkCryptoError>;
    match r_transactions {
        Ok(secret) => {
            r_secret = Ok(secret);
        }
        Err(e) => {
            eprint!("{:?}", e);
            // TODO change the error type.
            r_secret = Err(dk_crypto_error::DkCryptoError);
        }
    }
    r_secret
}


fn main() {
    const PROGRAM_NAME: &str = "PPM Pretty Password Manager";

    println!("😎 Init {}", PROGRAM_NAME);

    const PROJECT_CODE: &str = "ppm";
    const VAR_NAME: &str = "PPM_ENV";

    println!("😎 Config file using PROJECT_CODE={} VAR_NAME={}", PROJECT_CODE, VAR_NAME);

    let props = read_config(PROJECT_CODE, VAR_NAME);
    set_props(props);

    let port = get_prop_value("server.port").parse::<u16>().unwrap();
    let log_config: String = get_prop_value("log4rs.config");

    let log_config_path = Path::new(&log_config);

    println!("😎 Read log properties from {:?}", &log_config_path);

    match log4rs::init_file(&log_config_path, Default::default()) {
        Err(e) => {
            eprintln!("{:?} {:?}", &log_config_path, e);
            exit(-59);
        }
        Ok(_) => {}
    }

    info!("🚀 Start {}", PROGRAM_NAME);

    let mut my_config = Config::new(Environment::Production);
    my_config.set_port(port);

    let base_url = format!("/{}", PROJECT_CODE);
    let base_static_url = format!("/{}/static", PROJECT_CODE);

    rocket::custom(my_config)
        .mount(&base_static_url, StaticFiles::from("static"))
        .mount(&base_url, routes![
            history,
            add_key,
            decrypt_key,
            login,
            login_text,
            setup, transaction, search,
            index, search_page, input_page, style, script, resort_info, info_bar])
        .attach(CORS)
        .attach(Template::fairing())
        .launch();

    info!("🏁 End {}", PROGRAM_NAME);
}
