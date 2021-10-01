use crate::db::Connection;

use prettytable::{Attr, Cell, Row, Table};
use regex::Regex;
use std::env;

mod db;
mod tracker;

fn main() {
    let dist = if env::args().len() > 1 {
        env::args().nth(1).unwrap()
    } else {
        "sid".to_string()
    };

    let tracker = tracker::Tracker::new().unwrap();
    let debian = tracker.info().unwrap();

    let advisory_db_repo = rustsec::Repository::fetch(
        rustsec::repository::git::DEFAULT_URL,
        rustsec::Repository::default_path(),
        false,
    )
    .unwrap_or_else(|e| {
        eprintln!("couldn't fetch advisory database: {}", e);
        std::process::exit(1);
    });

    let database = rustsec::Database::load_from_repo(&advisory_db_repo).unwrap_or_else(|e| {
        eprintln!("error loading advisory database: {}", e);
        std::process::exit(1);
    });

    let mut conn = Connection::new().unwrap();
    let packages = conn.search(&dist).unwrap();

    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Source package").with_style(Attr::Bold),
        Cell::new("Version").with_style(Attr::Bold),
        Cell::new("Rust Advisory").with_style(Attr::Bold),
        Cell::new("Other Id").with_style(Attr::Bold),
        Cell::new("Bug in Debian").with_style(Attr::Bold),
    ]));
    for vuln in database.iter() {
        if let Some(col) = vuln.metadata.collection {
            if col == rustsec::collection::Collection::Rust {
                continue;
            }
        }
        if let Some(info) = &vuln.metadata.informational {
            if *info == rustsec::advisory::informational::Informational::Unmaintained {
                continue;
            }
        }
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
                let v: Vec<&str> = package.1.split('-').collect();
                let is_version_affected = vuln
                    .versions
                    .is_vulnerable(&rustsec::Version::parse(v[0]).unwrap());
                let mut row = vec![];
                if is_version_affected {
                    row.push(Cell::new(&package.0));
                    row.push(Cell::new(&package.1));
                    row.push(Cell::new(&vuln.metadata.id.as_str()));
                    row.push(Cell::new(
                        &vuln
                            .metadata
                            .aliases
                            .iter()
                            .map(|id| id.to_string() + "\n")
                            .collect::<String>(),
                    ));
                    row.push(Cell::new(&format!("{}", debian.contains_key(&package.0))));
                }
                if !row.is_empty() {
                    table.add_row(Row::new(row));
                }
            }
        }
    }
    table.printstd();
}
