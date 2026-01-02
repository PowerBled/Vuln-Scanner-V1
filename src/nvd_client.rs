use reqwest::Client;
use serde_json::Value;
use std::time::Duration;
use crate::vulnerabilities::Vulnerability;
use std::fs;
use std::path::Path;
use serde::Deserialize;
use colored::Colorize;

#[derive(Debug, Deserialize)]
struct Config {
    nvd_api_key: Option<String>,
}

pub struct NvdClient {
    client: Client,
    api_key: Option<String>,
    base_url: String,
}

impl NvdClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("VulnScanner/1.0")
            .build()?;
        
        // Пробуем получить API ключ разными способами
        let api_key = Self::get_api_key()?;
        
        Ok(Self {
            client,
            api_key,
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
        })
    }
    
    fn get_api_key() -> Result<Option<String>, Box<dyn std::error::Error>> {
        // Способ 1: Из переменной окружения
        #[cfg(target_os = "windows")]
        let env_key = std::env::var("NVD_API_KEY").ok();
        
        #[cfg(not(target_os = "windows"))]
        let env_key = std::env::var("NVD_API_KEY").ok();
        
        if let Some(key) = env_key {
            if !key.trim().is_empty() {
                println!("{} Используем NVD API ключ из переменной окружения", "✓".green());
                return Ok(Some(key));
            }
        }
        
        // Способ 2: Из файла конфигурации
        let config_path = "config.toml";
        if Path::new(config_path).exists() {
            match fs::read_to_string(config_path) {
                Ok(config_content) => {
                    match toml::from_str::<Config>(&config_content) {
                        Ok(config) => {
                            if let Some(key) = config.nvd_api_key {
                                if !key.trim().is_empty() {
                                    println!("{} Используем NVD API ключ из файла config.toml", "✓".green());
                                    return Ok(Some(key));
                                }
                            }
                        }
                        Err(_) => {
                            // Файл существует, но не является валидным TOML
                            println!("{} Файл config.toml существует, но содержит ошибки", "⚠".yellow());
                        }
                    }
                }
                Err(_) => {
                    // Не удалось прочитать файл
                    println!("{} Не удалось прочитать файл config.toml", "⚠".yellow());
                }
            }
        }
        
        // Способ 3: Из файла .env
        let env_path = ".env";
        if Path::new(env_path).exists() {
            match fs::read_to_string(env_path) {
                Ok(env_content) => {
                    for line in env_content.lines() {
                        if line.starts_with("NVD_API_KEY=") {
                            let key = line.trim_start_matches("NVD_API_KEY=").trim();
                            if !key.is_empty() {
                                println!("{} Используем NVD API ключ из файла .env", "✓".green());
                                return Ok(Some(key.to_string()));
                            }
                        }
                    }
                }
                Err(_) => {
                    println!("{} Не удалось прочитать файл .env", "⚠".yellow());
                }
            }
        }
        
        println!("{} NVD API ключ не найден. Проверка CVE будет ограничена.", "⚠".yellow());
        println!("{} Для полной функциональности:", "💡".cyan());
        println!("  1. Установите переменную окружения NVD_API_KEY");
        println!("  2. Создайте файл config.toml с ключом");
        println!("  3. Или создайте файл .env с ключом");
        
        Ok(None)
    }
    
    pub async fn check_vulnerability(&self, vuln: &Vulnerability) -> Option<String> {
        if let Some(cve) = &vuln.cve {
            if !cve.starts_with("CVE-") {
                return None;
            }
            
            // Пробуем получить информацию о CVE из NVD
            match self.get_cve_info(cve).await {
                Ok(info) => Some(info),
                Err(_) => None,
            }
        } else {
            // Ищем CVE по ключевым словам
            let keywords = self.extract_keywords(vuln);
            match self.search_cve(&keywords).await {
                Ok(info) => Some(info),
                Err(_) => None,
            }
        }
    }
    
    async fn get_cve_info(&self, cve_id: &str) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}?cveId={}", self.base_url, cve_id);
        
        let mut request = self.client.get(&url);
        
        if let Some(api_key) = &self.api_key {
            request = request.header("apiKey", api_key);
        }
        
        let response = request.send().await?;
        
        if response.status().is_success() {
            let json: Value = response.json().await?;
            
            if let Some(vulns) = json["vulnerabilities"].as_array() {
                if let Some(vuln) = vulns.first() {
                    if let Some(metrics) = vuln["cve"]["metrics"].as_object() {
                        if let Some(cvss_v3) = metrics.get("cvssMetricV31") {
                            if let Some(cvss_data) = cvss_v3.as_array() {
                                if let Some(first) = cvss_data.first() {
                                    if let Some(base_score) = first["cvssData"]["baseScore"].as_f64() {
                                        return Ok(format!("CVSS v3.1 Score: {:.1}", base_score));
                                    }
                                }
                            }
                        }
                    }
                    
                    if let Some(description) = vuln["cve"]["descriptions"].as_array() {
                        if let Some(en_desc) = description.iter().find(|d| d["lang"] == "en") {
                            if let Some(desc_text) = en_desc["value"].as_str() {
                                let truncated = if desc_text.len() > 200 {
                                    &desc_text[0..200]
                                } else {
                                    desc_text
                                };
                                return Ok(truncated.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        Ok("No NVD information available".to_string())
    }
    
    async fn search_cve(&self, keywords: &[String]) -> Result<String, Box<dyn std::error::Error>> {
        if keywords.is_empty() {
            return Ok("No keywords for search".to_string());
        }
        
        let keyword_search = keywords.join(" ");
        let url = format!("{}?keywordSearch={}", self.base_url, keyword_search);
        
        let mut request = self.client.get(&url);
        
        if let Some(api_key) = &self.api_key {
            request = request.header("apiKey", api_key);
        }
        
        let response = request.send().await?;
        
        if response.status().is_success() {
            let json: Value = response.json().await?;
            
            if let Some(total_results) = json["totalResults"].as_u64() {
                if total_results > 0 {
                    return Ok(format!("Found {} potential CVEs for: {}", total_results, keyword_search));
                }
            }
        }
        
        Ok("No matching CVEs found".to_string())
    }
    
    fn extract_keywords(&self, vuln: &Vulnerability) -> Vec<String> {
        let mut keywords = Vec::new();
        
        // Добавляем тип уязвимости
        keywords.push(vuln.vuln_type.as_str().to_string());
        
        // Добавляем ключевые слова из названия
        let title_lower = vuln.title.to_lowercase();
        if title_lower.contains("ssh") {
            keywords.push("ssh".to_string());
        }
        if title_lower.contains("apache") {
            keywords.push("apache".to_string());
        }
        if title_lower.contains("nginx") {
            keywords.push("nginx".to_string());
        }
        if title_lower.contains("mysql") {
            keywords.push("mysql".to_string());
        }
        if title_lower.contains("redis") {
            keywords.push("redis".to_string());
        }
        if title_lower.contains("elasticsearch") {
            keywords.push("elasticsearch".to_string());
        }
        
        // Добавляем порт как ключевое слово
        keywords.push(format!("port{}", vuln.port));
        
        keywords
    }
}

impl Clone for NvdClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
        }
    }
}