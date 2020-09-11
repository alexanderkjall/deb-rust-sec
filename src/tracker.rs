use anyhow::Result;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const CACHE_EXPIRE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    pub from: SystemTime,
    pub data: String,
}

#[derive(Serialize, Deserialize)]
pub struct Cve {
    pub description: Option<String>,
    pub scope: Option<String>,
    pub releases: HashMap<String, PackageInfo>
}

#[derive(Serialize, Deserialize)]
pub struct PackageInfo {
    status: String,
    repositories: HashMap<String, String>,
    fixed_version: Option<String>,
    urgency: String
}

pub struct Tracker {
    cache_dir: PathBuf,
}

impl Tracker {
    pub fn new() -> Result<Tracker> {
        let cache_dir = dirs::cache_dir().expect("cache directory not found")
            .join("deb-rust-sec");

        fs::create_dir_all(&cache_dir)?;

        Ok(Tracker {
            cache_dir,
        })
    }

    pub fn info(&self) -> Result<HashMap<String, HashMap<String, Cve>>> {
        let data = self.get_data()?;

        let info: HashMap<String, HashMap<String, Cve>> = serde_json::from_str(&data)?;

        Ok(info)
    }

    fn get_data(&self) -> Result<String> {
        if let Some(s) = self.check_cache()? {
            return Ok(s);
        }

        let res = reqwest::blocking::get("https://security-tracker.debian.org/tracker/data/json")?;
        let body = res.text()?;

        self.write_cache(&body)?;

        return Ok(body);
    }

    fn cache_path(&self) -> PathBuf {
        self.cache_dir.join("tracker-data")
    }

    fn check_cache(&self) -> Result<Option<String>> {
        let path = self.cache_path();

        if !path.exists() {
            return Ok(None);
        }

        let buf = fs::read(path)?;
        let cache: CacheEntry = serde_json::from_slice(&buf)?;

        if SystemTime::now().duration_since(cache.from)? > CACHE_EXPIRE {
            Ok(None)
        } else {
            Ok(Some(cache.data))
        }
    }

    fn write_cache(&self, s: &str) -> Result<()> {
        let cache = CacheEntry {
            from: SystemTime::now(),
            data: s.to_string(),
        };
        let buf = serde_json::to_vec(&cache)?;
        fs::write(self.cache_path(), &buf)?;
        Ok(())
    }
}