use anyhow::Error;
use postgres::{Client, NoTls};
use serde::{Serialize, Deserialize};
use serde_json;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};


const POSTGRES: &str = "postgresql://udd-mirror:udd-mirror@udd-mirror.debian.net/udd";
const CACHE_EXPIRE: Duration = Duration::from_secs(90 * 60);

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    pub from: SystemTime,
    pub list: Vec<(String, String)>,
}

pub struct Connection {
    client: postgres::Client,
    cache_dir: PathBuf,
}

impl Connection {
    pub fn new() -> Result<Connection, Error> {
        let client = Client::connect(POSTGRES, NoTls)?;

        let cache_dir = dirs::cache_dir().expect("cache directory not found")
                                         .join("deb-rust-sec");

        fs::create_dir_all(&cache_dir)?;

        Ok(Connection {
            client,
            cache_dir,
        })
    }

    fn cache_path(&self, release: &str) -> PathBuf {
        self.cache_dir.join(release)
    }

    fn check_cache(&self, release: &str) -> Result<Option<Vec<(String, String)>>, Error> {
        let path = self.cache_path(release);

        if !path.exists() {
            return Ok(None);
        }

        let buf = fs::read(path)?;
        let cache: CacheEntry = serde_json::from_slice(&buf)?;

        if SystemTime::now().duration_since(cache.from)? > CACHE_EXPIRE {
            Ok(None)
        } else {
            Ok(Some(cache.list))
        }
    }

    fn write_cache(&self, release: &str, result: &Vec<(String, String)>) -> Result<(), Error> {
        let cache = CacheEntry {
            from: SystemTime::now(),
            list: result.clone(),
        };
        let buf = serde_json::to_vec(&cache)?;
        fs::write(self.cache_path(release), &buf)?;
        Ok(())
    }

    pub fn search(&mut self, release: &str) -> Result<Vec<(String, String)>, Error> {
        if let Ok(rows_opt) = self.check_cache(release) {
            if let Some(rows) = rows_opt {
                return Ok(rows);
            }
        }
        let rows = self.client.query("select source::text, version::text from sources where bin like 'librust%' and release=$1;",
                                        &[&release.to_string()])?;

        let mut result: Vec<(String, String)> = vec![];
        for row in &rows {
            let source_name: String = row.get(0);
            let debversion: String = row.get(1);

            result.push((source_name, debversion))
        }
        self.write_cache(release, &result)?;
        Ok(result)
    }
}
