use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;
use crate::vulnerabilities::{Vulnerability, VulnerabilityType, Severity};

pub struct WebScanner {
    client: Client,
}

impl WebScanner {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
    
    pub async fn deep_scan(&self, ip: IpAddr, port: u16) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let protocol = if port == 443 || port == 8443 { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, ip, port);
        
        // Проверка стандартных уязвимостей
        if let Some(vuln) = self.check_directory_listing(&base_url).await {
            vulnerabilities.push(vuln);
        }
        if let Some(vuln) = self.check_debug_endpoints(&base_url).await {
            vulnerabilities.push(vuln);
        }
        if let Some(vuln) = self.check_default_credentials(&base_url).await {
            vulnerabilities.push(vuln);
        }
        if let Some(vuln) = self.check_information_disclosure(&base_url).await {
            vulnerabilities.push(vuln);
        }
        if let Some(vuln) = self.check_csrf_vulnerabilities(&base_url).await {
            vulnerabilities.push(vuln);
        }
        if let Some(vuln) = self.check_clickjacking(&base_url).await {
            vulnerabilities.push(vuln);
        }
        if let Some(vuln) = self.check_security_headers(&base_url).await {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    async fn check_directory_listing(&self, base_url: &str) -> Option<Vulnerability> {
        let test_paths = [
            "/admin/",
            "/backup/",
            "/config/",
            "/db/",
            "/data/",
            "/uploads/",
            "/logs/",
            "/temp/",
            "/tmp/",
        ];
        
        for path in &test_paths {
            let url = format!("{}{}", base_url, path);
            if let Ok(response) = self.client.get(&url).timeout(Duration::from_secs(2)).send().await {
                if response.status().is_success() {
                    let body = response.text().await.unwrap_or_default();
                    if body.contains("<title>Index of") || body.contains("Directory listing for") {
                        return Some(Vulnerability {
                            ip: extract_ip_from_url(base_url),
                            port: extract_port_from_url(base_url),
                            title: "Включено листинг директорий".to_string(),
                            description: format!("Листинг директорий включен для {}", url),
                            cve: Some("CWE-548".to_string()),
                            severity: Severity::Medium,
                            vuln_type: VulnerabilityType::InformationDisclosure,
                            exploitation: "Прямой доступ к файлам".to_string(),
                            recommendation: "Отключить Indexes в конфигурации".to_string(),
                        });
                    }
                }
            }
        }
        None
    }
    
    async fn check_debug_endpoints(&self, base_url: &str) -> Option<Vulnerability> {
        let debug_paths = [
            "/debug/",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/console/",
            "/actuator/health",
            "/actuator/info",
            "/wp-admin/",
            "/adminer.php",
            "/pma/",
        ];
        
        for path in &debug_paths {
            let url = format!("{}{}", base_url, path);
            if let Ok(response) = self.client.get(&url).timeout(Duration::from_secs(2)).send().await {
                if response.status().is_success() {
                    let body = response.text().await.unwrap_or_default();
                    
                    if body.contains("phpinfo()") || body.contains("PHP Version") {
                        return Some(Vulnerability {
                            ip: extract_ip_from_url(base_url),
                            port: extract_port_from_url(base_url),
                            title: "Открытая страница phpinfo".to_string(),
                            description: "Информация о PHP конфигурации доступна публично".to_string(),
                            cve: Some("CWE-200".to_string()),
                            severity: Severity::Medium,
                            vuln_type: VulnerabilityType::InformationDisclosure,
                            exploitation: "Утечка информации о системе".to_string(),
                            recommendation: "Удалить или защитить phpinfo".to_string(),
                        });
                    }
                    
                    if body.contains("Adminer") || body.contains("phpMyAdmin") {
                        return Some(Vulnerability {
                            ip: extract_ip_from_url(base_url),
                            port: extract_port_from_url(base_url),
                            title: "Панель администратора базы данных доступна".to_string(),
                            description: "Интерфейс управления БД доступен публично".to_string(),
                            cve: Some("CWE-284".to_string()),
                            severity: Severity::High,
                            vuln_type: VulnerabilityType::Misconfiguration,
                            exploitation: "Атаки на аутентификацию БД".to_string(),
                            recommendation: "Ограничить доступ по IP или удалить".to_string(),
                        });
                    }
                }
            }
        }
        None
    }
    
    async fn check_default_credentials(&self, base_url: &str) -> Option<Vulnerability> {
        // Проверка страниц входа
        let login_paths = [
            "/login",
            "/admin",
            "/wp-login.php",
            "/administrator",
            "/cpanel",
        ];
        
        for path in &login_paths {
            let url = format!("{}{}", base_url, path);
            if let Ok(response) = self.client.get(&url).timeout(Duration::from_secs(2)).send().await {
                if response.status().is_success() {
                    let body = response.text().await.unwrap_or_default().to_lowercase();
                    
                    if body.contains("password") && (body.contains("login") || body.contains("sign in")) {
                        return Some(Vulnerability {
                            ip: extract_ip_from_url(base_url),
                            port: extract_port_from_url(base_url),
                            title: "Страница входа доступна".to_string(),
                            description: "Возможно использование стандартных учетных данных".to_string(),
                            cve: Some("CWE-521".to_string()),
                            severity: Severity::Medium,
                            vuln_type: VulnerabilityType::Misconfiguration,
                            exploitation: "Подбор стандартных паролей".to_string(),
                            recommendation: "Изменить стандартные учетные данные".to_string(),
                        });
                    }
                }
            }
        }
        None
    }
    
    async fn check_information_disclosure(&self, base_url: &str) -> Option<Vulnerability> {
        let test_paths = [
            "/.git/HEAD",
            "/.env",
            "/config.php",
            "/database.yml",
            "/docker-compose.yml",
            "/README.md",
            "/CHANGELOG.md",
            "/package.json",
        ];
        
        for path in &test_paths {
            let url = format!("{}{}", base_url, path);
            if let Ok(response) = self.client.get(&url).timeout(Duration::from_secs(2)).send().await {
                if response.status().is_success() {
                    return Some(Vulnerability {
                        ip: extract_ip_from_url(base_url),
                        port: extract_port_from_url(base_url),
                        title: "Утечка конфиденциальной информации".to_string(),
                        description: format!("Файл {} доступен публично", path),
                        cve: Some("CWE-200".to_string()),
                        severity: Severity::Low,
                        vuln_type: VulnerabilityType::InformationDisclosure,
                        exploitation: "Прямой доступ к конфигурационным файлам".to_string(),
                        recommendation: "Удалить или ограничить доступ к файлам".to_string(),
                    });
                }
            }
        }
        None
    }
    
    async fn check_csrf_vulnerabilities(&self, base_url: &str) -> Option<Vulnerability> {
        // Базовая проверка CSRF токенов
        let test_paths = ["/login", "/profile", "/settings"];
        
        for path in &test_paths {
            let url = format!("{}{}", base_url, path);
            if let Ok(response) = self.client.get(&url).timeout(Duration::from_secs(2)).send().await {
                if response.status().is_success() {
                    let body = response.text().await.unwrap_or_default();
                    
                    // Проверка наличия CSRF токенов в формах
                    let has_form = body.contains("<form");
                    let has_csrf = body.contains("csrf") || body.contains("_token") || 
                                  body.contains("authenticity_token") || body.contains("csrfmiddlewaretoken");
                    
                    if has_form && !has_csrf {
                        return Some(Vulnerability {
                            ip: extract_ip_from_url(base_url),
                            port: extract_port_from_url(base_url),
                            title: "Возможная CSRF уязвимость".to_string(),
                            description: "Формы могут не иметь CSRF защиты".to_string(),
                            cve: Some("CWE-352".to_string()),
                            severity: Severity::Medium,
                            vuln_type: VulnerabilityType::WebServer,
                            exploitation: "Cross-Site Request Forgery атаки".to_string(),
                            recommendation: "Добавить CSRF токены".to_string(),
                        });
                    }
                }
            }
        }
        None
    }
    
    async fn check_clickjacking(&self, base_url: &str) -> Option<Vulnerability> {
        let url = format!("{}", base_url);
        if let Ok(response) = self.client.get(&url).timeout(Duration::from_secs(2)).send().await {
            if let Some(x_frame_options) = response.headers().get("X-Frame-Options") {
                let value = x_frame_options.to_str().unwrap_or("");
                if value == "DENY" || value == "SAMEORIGIN" {
                    return None; // Защищено
                }
            }
            
            if let Some(content_security_policy) = response.headers().get("Content-Security-Policy") {
                let value = content_security_policy.to_str().unwrap_or("");
                if value.contains("frame-ancestors") {
                    return None; // Защищено
                }
            }
            
            // Если нет защиты от clickjacking
            return Some(Vulnerability {
                ip: extract_ip_from_url(base_url),
                port: extract_port_from_url(base_url),
                title: "Возможная Clickjacking уязвимость".to_string(),
                description: "Отсутствуют заголовки защиты от clickjacking".to_string(),
                cve: Some("CWE-1021".to_string()),
                severity: Severity::Low,
                vuln_type: VulnerabilityType::WebServer,
                exploitation: "Атаки Clickjacking/UI Redress".to_string(),
                recommendation: "Добавить X-Frame-Options или CSP".to_string(),
            });
        }
        None
    }
    
    async fn check_security_headers(&self, base_url: &str) -> Option<Vulnerability> {
        let url = format!("{}", base_url);
        if let Ok(response) = self.client.get(&url).timeout(Duration::from_secs(2)).send().await {
            let mut missing_headers = Vec::new();
            
            if response.headers().get("X-Content-Type-Options").is_none() {
                missing_headers.push("X-Content-Type-Options");
            }
            
            if response.headers().get("X-XSS-Protection").is_none() {
                missing_headers.push("X-XSS-Protection");
            }
            
            if response.headers().get("Strict-Transport-Security").is_none() {
                missing_headers.push("Strict-Transport-Security");
            }
            
            if !missing_headers.is_empty() {
                return Some(Vulnerability {
                    ip: extract_ip_from_url(base_url),
                    port: extract_port_from_url(base_url),
                    title: "Отсутствуют security headers".to_string(),
                    description: format!("Отсутствуют заголовки: {}", missing_headers.join(", ")),
                    cve: Some("CWE-693".to_string()),
                    severity: Severity::Low,
                    vuln_type: VulnerabilityType::WebServer,
                    exploitation: "Увеличение поверхности атаки".to_string(),
                    recommendation: "Добавить security headers".to_string(),
                });
            }
        }
        None
    }
}

impl Clone for WebScanner {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

fn extract_ip_from_url(url: &str) -> String {
    url.split("://").nth(1)
        .and_then(|s| s.split(':').next())
        .unwrap_or("unknown")
        .to_string()
}

fn extract_port_from_url(url: &str) -> u16 {
    url.split("://").nth(1)
        .and_then(|s| s.split(':').nth(1))
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(80)
}