use colored::*;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn color(&self) -> ColoredString {
        match self {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".bright_red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".cyan(),
            Severity::Info => "INFO".blue(),
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilityType {
    SSH,
    WebServer,
    Database,
    Misconfiguration,
    InformationDisclosure,
    SearchEngine,
    Unknown,
}

impl VulnerabilityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnerabilityType::SSH => "SSH",
            VulnerabilityType::WebServer => "Web Server",
            VulnerabilityType::Database => "Database",
            VulnerabilityType::Misconfiguration => "Misconfiguration",
            VulnerabilityType::InformationDisclosure => "Information Disclosure",
            VulnerabilityType::SearchEngine => "Search Engine",
            VulnerabilityType::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub ip: String,
    pub port: u16,
    pub title: String,
    pub description: String,
    pub cve: Option<String>,
    pub severity: Severity,
    pub vuln_type: VulnerabilityType,
    pub exploitation: String,
    pub recommendation: String,
}

impl Vulnerability {
    pub fn to_markdown(&self) -> String {
        format!(
            "## {}\n\n\
            **IP:** {}\n\
            **Port:** {}\n\
            **Severity:** {}\n\
            **Type:** {}\n\
            **CVE:** {}\n\n\
            **Description:**\n{}\n\n\
            **Exploitation:**\n{}\n\n\
            **Recommendation:**\n{}\n\n\
            ---\n",
            self.title,
            self.ip,
            self.port,
            self.severity.as_str(),
            self.vuln_type.as_str(),
            self.cve.as_deref().unwrap_or("N/A"),
            self.description,
            self.exploitation,
            self.recommendation
        )
    }
    
    pub fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},\"{}\",\"{}\",\"{}\"",
            self.ip,
            self.port,
            self.title,
            self.severity.as_str(),
            self.vuln_type.as_str(),
            self.cve.as_deref().unwrap_or("N/A"),
            self.description.replace("\"", "\"\""),
            self.exploitation.replace("\"", "\"\""),
            self.recommendation.replace("\"", "\"\"")
        )
    }
}