use crate::db::Connection;

use std::env;
use regex::Regex;

mod db;
mod tracker;

fn main() {
    let dist = if env::args().len() > 1 {
        env::args().skip(1).next().unwrap()
    } else {
        "sid".to_string()
    };

    let tracker = tracker::Tracker::new().unwrap();
    let debian = tracker.info().unwrap();

    let advisory_db_repo = rustsec::Repository::fetch(rustsec::repository::DEFAULT_URL, rustsec::Repository::default_path(), false)
        .unwrap_or_else(|e| {
            eprintln!("couldn't fetch advisory database: {}", e);
            std::process::exit(1);
        });

    let database = rustsec::Database::load(&advisory_db_repo).unwrap_or_else(|e| {
        eprintln!("error loading advisory database: {}", e);
        std::process::exit(1);
    });

    let mut conn = Connection::new().unwrap();
    let packages = conn.search(&dist).unwrap();

    for vuln in database.iter() {
        let vuln_crate = vuln.metadata.package.as_str().replace("_", "-");
        for package in &packages {
            let name = &package.0.replace("_", "-")[5..];
            let ver_exist = if name.len() > vuln_crate.len() && name.starts_with(&vuln_crate) {
                let re = Regex::new(r"^\d.\d").unwrap();
                re.is_match(&name[(vuln_crate.len() + 1)..])
            } else {
                false
            };
            if vuln_crate == name || ver_exist {
                let v:Vec<&str> = package.1.split("-").collect();
                let is_version_affected = vuln.versions.is_vulnerable(&rustsec::version::Version::parse(v[0]).unwrap());
                if is_version_affected {
                    print!("{} : {}, ({}) {}", package.0, package.1, is_version_affected, &vuln.metadata.id.as_str());
                    for id in &vuln.metadata.aliases {
                        print!(" {}", id.as_str());
                    }
                    println!();
                }
            }
        }
    }
}
