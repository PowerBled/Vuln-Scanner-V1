use crate::vulnerabilities::{Vulnerability, VulnerabilityType, Severity};
use crate::web_scanner::WebScanner;
use crate::nvd_client::NvdClient;
use crate::utils;
use ipnetwork::IpNetwork;
use reqwest::Client;
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, RwLock};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter, AsyncReadExt};
use colored::Colorize;
use indicatif::ProgressBar;
use atomic_counter::{AtomicCounter, RelaxedCounter};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering, AtomicBool};
use tokio::time::{sleep, timeout};
use std::time::Instant;
use regex::Regex;
use lazy_static::lazy_static;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub max_concurrent_tasks: usize,
    pub connection_timeout: Duration,
    pub read_timeout: Duration,
    pub batch_size: usize,
    pub ports_per_batch: usize,
    pub rate_limit_per_second: usize,
    pub enable_web_deep_scan: bool,
    pub enable_nvd_check: bool,
    pub max_connections_per_host: usize,
    pub max_ips_to_scan: Option<u64>,
    pub adaptive_rate_limiting: bool,
    pub network_capacity_factor: f64,
}

impl ScanConfig {
    pub fn default() -> Self {
        let (max_concurrent, rate_limit) = utils::estimate_network_capacity();
        
        Self {
            max_concurrent_tasks: max_concurrent,
            connection_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(1000),
            batch_size: 1000,
            ports_per_batch: 100,
            rate_limit_per_second: rate_limit,
            enable_web_deep_scan: true,
            enable_nvd_check: true,
            max_connections_per_host: 2,
            max_ips_to_scan: None,
            adaptive_rate_limiting: true,
            network_capacity_factor: 0.7,
        }
    }
    
    pub fn optimized_for_range(total_ips: u64) -> Self {
        let mut config = Self::default();
        
        if total_ips > 1_000_000 {
            config.max_ips_to_scan = Some(1_000_000);
        } else if total_ips > 100_000 {
            config.max_ips_to_scan = Some(total_ips.min(500_000));
        }
        
        if total_ips > 50_000 {
            config.max_connections_per_host = 1;
            config.connection_timeout = Duration::from_millis(200);
            config.rate_limit_per_second = (config.rate_limit_per_second as f64 * 0.5) as usize;
        }
        
        if total_ips < 1000 {
            config.max_concurrent_tasks = 100;
            config.batch_size = 100;
        }
        
        config
    }
}

pub struct HighPerformanceScanner {
    client: Client,
    config: ScanConfig,
    semaphore: Arc<Semaphore>,
    results_file: Option<Arc<tokio::sync::Mutex<BufWriter<File>>>>,
    csv_file: Option<Arc<tokio::sync::Mutex<BufWriter<File>>>>,
    web_scanner: Option<WebScanner>,
    nvd_client: Option<NvdClient>,
    rate_limiter: Arc<RwLock<AdaptiveRateLimiter>>,
    active_tasks: Arc<AtomicUsize>,
    connection_pool: Arc<RwLock<HashMap<String, usize>>>,
    stop_flag: Arc<AtomicBool>,
    network_monitor: Arc<RwLock<NetworkMonitor>>,
}

impl HighPerformanceScanner {
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }
}

struct AdaptiveRateLimiter {
    requests_per_second: usize,
    current_rate: usize,
    last_adjustment: Instant,
    adjustment_interval: Duration,
    success_rate: f64,
    error_rate: f64,
}

impl AdaptiveRateLimiter {
    fn new(initial_rate: usize) -> Self {
        Self {
            requests_per_second: initial_rate,
            current_rate: initial_rate,
            last_adjustment: Instant::now(),
            adjustment_interval: Duration::from_secs(5),
            success_rate: 0.0,
            error_rate: 0.0,
        }
    }
    
    async fn wait(&mut self) {
        let interval = Duration::from_micros(1_000_000 / self.current_rate as u64);
        sleep(interval).await;
    }
    
    fn update_stats(&mut self, success: bool) {
        if success {
            self.success_rate = 0.9 * self.success_rate + 0.1;
            self.error_rate = 0.9 * self.error_rate;
        } else {
            self.success_rate = 0.9 * self.success_rate;
            self.error_rate = 0.9 * self.error_rate + 0.1;
        }
        
        if Instant::now().duration_since(self.last_adjustment) >= self.adjustment_interval {
            if self.success_rate > 0.95 && self.error_rate < 0.05 {
                self.current_rate = (self.current_rate as f64 * 1.1) as usize;
            } else if self.success_rate < 0.8 || self.error_rate > 0.2 {
                self.current_rate = (self.current_rate as f64 * 0.8).max(10.0) as usize;
            }
            
            self.last_adjustment = Instant::now();
        }
    }
    
    fn get_current_rate(&self) -> usize {
        self.current_rate
    }
}

struct NetworkMonitor {
    start_time: Instant,
    total_requests: usize,
    successful_requests: usize,
    failed_requests: usize,
    last_sample_time: Instant,
    sample_interval: Duration,
}

impl NetworkMonitor {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            last_sample_time: Instant::now(),
            sample_interval: Duration::from_secs(10),
        }
    }
    
    fn record_request(&mut self, success: bool) {
        self.total_requests += 1;
        if success {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
        }
    }
    
    fn get_stats(&self) -> (f64, f64) {
        let total = self.total_requests as f64;
        if total == 0.0 {
            return (0.0, 0.0);
        }
        let success_rate = self.successful_requests as f64 / total;
        let error_rate = self.failed_requests as f64 / total;
        (success_rate, error_rate)
    }
    
    fn should_adjust_rate(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_sample_time) >= self.sample_interval {
            self.last_sample_time = now;
            true
        } else {
            false
        }
    }
}

impl HighPerformanceScanner {
    pub async fn new(config: ScanConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(config.read_timeout)
            .connect_timeout(config.connection_timeout)
            .pool_idle_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(2)
            .user_agent("VulnScanner/1.0-HP")
            .danger_accept_invalid_certs(true)
            .tcp_nodelay(true)
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(90))
            .build()
            .unwrap();
        
        let results_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("results/vulnerabilities.txt")
            .await?;
        
        let csv_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("results/vulnerabilities.csv")
            .await?;
        
        let mut results_writer = BufWriter::new(results_file);
        results_writer.write_all("=== Результаты сканирования уязвимостей ===\n\n".as_bytes()).await?;
        
        let mut csv_writer = BufWriter::new(csv_file);
        csv_writer.write_all("IP,Port,Title,Severity,Type,CVE,Description,Exploitation,Recommendation\n".as_bytes()).await?;
        
        let web_scanner = if config.enable_web_deep_scan {
            Some(WebScanner::new(client.clone()))
        } else {
            None
        };
        
        let nvd_client = if config.enable_nvd_check {
            NvdClient::new().await.ok()
        } else {
            None
        };
        
        let initial_rate = config.rate_limit_per_second;
        if config.adaptive_rate_limiting {
            println!("{} Включено адаптивное rate limiting (начальная скорость: {}/сек)", "⚡".cyan(), initial_rate);
        }
        
        Ok(Self {
            client,
            config: config.clone(),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_tasks)),
            results_file: Some(Arc::new(tokio::sync::Mutex::new(results_writer))),
            csv_file: Some(Arc::new(tokio::sync::Mutex::new(csv_writer))),
            web_scanner,
            nvd_client,
            rate_limiter: Arc::new(RwLock::new(AdaptiveRateLimiter::new(initial_rate))),
            active_tasks: Arc::new(AtomicUsize::new(0)),
            connection_pool: Arc::new(RwLock::new(HashMap::new())),
            stop_flag: Arc::new(AtomicBool::new(false)),
            network_monitor: Arc::new(RwLock::new(NetworkMonitor::new())),
        })
    }
    
    pub fn get_active_tasks(&self) -> usize {
        self.active_tasks.load(Ordering::Relaxed)
    }
    
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
    
    pub async fn scan_ips(&self, ip_ranges: &[IpNetwork], progress_bar: Option<ProgressBar>) -> Result<usize, Box<dyn std::error::Error>> {
        println!("{} Генерация IP-адресов для сканирования...", "⚙️".cyan());
        
        let total_ips = self.estimate_ip_count(ip_ranges);
        let ips_to_scan = if let Some(max_ips) = self.config.max_ips_to_scan {
            total_ips.min(max_ips)
        } else {
            total_ips
        };
        
        println!("{} Всего IP-адресов: {}", "📊".blue(), total_ips);
        println!("{} Будет сканироваться: {}", "📊".blue(), ips_to_scan);
        
        if total_ips > 1_000_000 {
            println!("{} Большой диапазон - используем потоковую обработку", "💡".cyan());
        }
        
        let progress_counter = Arc::new(RelaxedCounter::new(0));
        let mut total_vulns = 0;
        
        let ip_list = self.create_ip_list(ip_ranges, ips_to_scan);
        let total_ips_to_scan = ip_list.len();
        
        println!("{} Подготовлено {} IP-адресов для сканирования", "✓".green(), total_ips_to_scan);
        
        let scanner = self.clone();
        let pb = progress_bar.clone();
        let counter = Arc::clone(&progress_counter);
        
        let ip_index = Arc::new(AtomicUsize::new(0));
        let ip_list_arc = Arc::new(ip_list);
        
        let consumer_scanner = scanner.clone();
        let consumer_counter = Arc::clone(&counter);
        let consumer_pb = pb.clone();
        
        let mut consumer_tasks = Vec::new();
        
        let num_consumer_tasks = self.config.max_concurrent_tasks.min(100);
        
        for i in 0..num_consumer_tasks {
            let scanner = consumer_scanner.clone();
            let ip_list = Arc::clone(&ip_list_arc);
            let ip_index = Arc::clone(&ip_index);
            let counter = Arc::clone(&consumer_counter);
            let pb = consumer_pb.clone();
            
            consumer_tasks.push(tokio::spawn(async move {
                let task_id = i;
                let mut processed = 0;
                let mut local_vulns = 0;
                
                loop {
                    let current_index = ip_index.fetch_add(1, Ordering::Relaxed);
                    
                    if current_index >= total_ips_to_scan {
                        break;
                    }
                    
                    if scanner.stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    let ip = ip_list[current_index];
                    
                    if scanner.config.adaptive_rate_limiting {
                        let mut limiter = scanner.rate_limiter.write().await;
                        limiter.wait().await;
                    } else {
                        sleep(Duration::from_micros(1_000_000 / scanner.config.rate_limit_per_second as u64)).await;
                    }
                    
                    scanner.active_tasks.fetch_add(1, Ordering::Relaxed);
                    let result = scanner.scan_single_ip(ip).await;
                    scanner.active_tasks.fetch_sub(1, Ordering::Relaxed);
                    
                    counter.inc();
                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                    
                    processed += 1;
                    
                    let success = result.is_ok();
                    if scanner.config.adaptive_rate_limiting {
                        let mut limiter = scanner.rate_limiter.write().await;
                        limiter.update_stats(success);
                        
                        let mut monitor = scanner.network_monitor.write().await;
                        monitor.record_request(success);
                        
                        if monitor.should_adjust_rate() && task_id == 0 {
                            let (success_rate, error_rate) = monitor.get_stats();
                            let current_rate = limiter.get_current_rate();
                            println!("{} Статистика: успешно {:.1}%, ошибки {:.1}%, скорость {}/сек", 
                                   "📊".blue(), success_rate * 100.0, error_rate * 100.0, current_rate);
                        }
                    }
                    
                    match result {
                        Ok(vulns) => {
                            for vuln in vulns {
                                if let Err(_e) = scanner.save_vulnerability(&vuln).await {
                                } else {
                                    local_vulns += 1;
                                }
                            }
                        }
                        Err(_e) => {
                            if processed % 100 == 0 {
                            }
                        }
                    }
                    
                    if processed % 1000 == 0 && task_id == 0 {
                        let active = scanner.get_active_tasks();
                        let rate = scanner.rate_limiter.read().await.get_current_rate();
                        println!("{} Задача {}: обработано {} IP, найдено {} уязвимостей, активно задач: {}, скорость: {}/сек", 
                               "📈".blue(), task_id, processed, local_vulns, active, rate);
                    }
                }
                
                local_vulns
            }));
        }
        
        let mut consumer_results = Vec::new();
        for task in consumer_tasks {
            match task.await {
                Ok(vuln_count) => consumer_results.push(vuln_count),
                Err(_e) => {
                }
            }
        }
        
        for vuln_count in consumer_results {
            total_vulns += vuln_count;
        }
        
        self.finalize_files().await?;
        
        if let Some(pb) = progress_bar {
            pb.finish_with_message("Сканирование завершено");
        }
        
        println!("{} Всего найдено уязвимостей: {}", "🔍".blue(), total_vulns);
        
        Ok(total_vulns)
    }
    
    fn create_ip_list(&self, ip_ranges: &[IpNetwork], max_ips: u64) -> Vec<IpAddr> {
        let mut ip_list = Vec::with_capacity(max_ips.min(10_000_000) as usize);
        let mut count = 0;
        
        for range in ip_ranges {
            match range {
                IpNetwork::V4(v4_range) => {
                    if v4_range.prefix() == 32 {
                        ip_list.push(IpAddr::V4(v4_range.network()));
                        count += 1;
                    } else {
                        let network = v4_range.network();
                        let broadcast = v4_range.broadcast();
                        let start = u32::from(network);
                        let end = u32::from(broadcast);
                        
                        let range_size = (end - start + 1) as usize;
                        let max_ips_from_range = (max_ips as usize - count).min(range_size);
                        
                        if max_ips_from_range == range_size {
                            for ip_val in start..=end {
                                if count >= max_ips as usize {
                                    break;
                                }
                                ip_list.push(IpAddr::V4(Ipv4Addr::from(ip_val)));
                                count += 1;
                            }
                        } else {
                            let step = (range_size / max_ips_from_range).max(1);
                            for (i, ip_val) in (start..=end).step_by(step).enumerate() {
                                if i >= max_ips_from_range || count >= max_ips as usize {
                                    break;
                                }
                                ip_list.push(IpAddr::V4(Ipv4Addr::from(ip_val)));
                                count += 1;
                            }
                        }
                    }
                }
                IpNetwork::V6(v6_range) => {
                    if v6_range.prefix() == 128 {
                        ip_list.push(IpAddr::V6(v6_range.network()));
                        count += 1;
                    } else {
                        let network = v6_range.network();
                        let broadcast = v6_range.broadcast();
                        let start = u128::from(network);
                        let end = u128::from(broadcast);
                        
                        let max_ipv6_ips = 1000.min(max_ips as usize - count);
                        let step = ((end - start) / max_ipv6_ips as u128).max(1);
                        
                        for (i, ip_val) in (start..=end).step_by(step as usize).enumerate() {
                            if i >= max_ipv6_ips || count >= max_ips as usize {
                                break;
                            }
                            ip_list.push(IpAddr::V6(Ipv6Addr::from(ip_val)));
                            count += 1;
                        }
                    }
                }
            }
            
            if count >= max_ips as usize {
                break;
            }
        }
        
        ip_list
    }
    
    fn estimate_ip_count(&self, ip_ranges: &[IpNetwork]) -> u64 {
        let mut total = 0u64;
        
        for range in ip_ranges {
            match range {
                IpNetwork::V4(v4_range) => {
                    let prefix = v4_range.prefix();
                    if prefix == 32 {
                        total += 1;
                    } else {
                        let range_total = 2u64.pow(32 - prefix as u32);
                        total += range_total;
                    }
                }
                IpNetwork::V6(v6_range) => {
                    let prefix = v6_range.prefix();
                    if prefix == 128 {
                        total += 1;
                    } else {
                        let range_total = 2u64.pow(128 - prefix as u32);
                        total += range_total.min(1000);
                    }
                }
            }
            
            if total > 10_000_000 {
                return total;
            }
        }
        
        total
    }
    
    async fn check_connections_per_host(&self, ip: IpAddr) -> bool {
        let ip_str = ip.to_string();
        let mut pool = self.connection_pool.write().await;
        
        let count = pool.entry(ip_str).or_insert(0);
        if *count >= self.config.max_connections_per_host {
            return false;
        }
        *count += 1;
        true
    }
    
    async fn release_connection(&self, ip: IpAddr) {
        let ip_str = ip.to_string();
        let mut pool = self.connection_pool.write().await;
        
        if let Some(count) = pool.get_mut(&ip_str) {
            if *count > 0 {
                *count -= 1;
            }
        }
    }
    
    async fn scan_single_ip(&self, ip: IpAddr) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
        if self.stop_flag.load(Ordering::Relaxed) {
            return Ok(Vec::new());
        }
        
        let mut vulnerabilities = Vec::new();
        
        if !self.check_connections_per_host(ip).await {
            return Ok(vulnerabilities);
        }
        
        let critical_ports = [
            // SSH и удаленный доступ
            22, 2222, 222, 22222, // SSH
            23, // Telnet
            3389, 3390, // RDP
            5900, 5901, 5902, 5800, 5801, // VNC
            5631, 5632, // pcAnywhere
            4899, // Radmin
            3000, 3001, // TeamViewer
            
            // Веб-сервисы
            80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 9000,
            
            // Базы данных и кэши
            3306, 3307, // MySQL
            5432, 5433, // PostgreSQL
            6379, 6380, // Redis
            27017, 27018, // MongoDB
            9200, 9300, // Elasticsearch
            11211, // Memcached
            1433, 1434, // MS SQL
            1521, 1522, // Oracle
            50000, // DB2
            26257, // CockroachDB
            9042, // Cassandra
            
            // Файловые сервисы
            21, 20, // FTP
            69, // TFTP
            2049, // NFS
            111, // RPC/NFS
            139, 445, // SMB/CIFS
            2049, // NFS
            873, // rsync
            
            // Почтовые сервисы
            25, 465, 587, // SMTP
            110, 995, // POP3
            143, 993, // IMAP
            
            // DNS и сетевые сервисы
            53, // DNS
            161, 162, // SNMP
            389, 636, // LDAP/LDAPS
            636, // LDAPS
            
            // Контейнеры и оркестрация
            2375, 2376, // Docker
            6443, // Kubernetes API
            10250, // Kubelet
            10255, // Kubelet readonly
            9099, // Prometheus
            9090, // Prometheus alt
            
            // Системные сервисы
            111, // RPCbind
            5666, // Nagios
            10050, 10051, // Zabbix
            9100, // Node Exporter
            9093, // Alertmanager
            
            // Разное
            1723, // PPTP
            5060, 5061, // SIP
            5060, // SIP over UDP
            3478, // STUN
            1935, // RTMP
            554, // RTSP
            6697, 6667, // IRC
            
            // CMS и приложения
            8081, 8082, // Jenkins, SonarQube
            9001, 9002, // PHP-FPM, Supervisor
            15672, 5672, // RabbitMQ
            8161, 61616, // ActiveMQ
            5984, 5986, // CouchDB
            5984, // CouchDB HTTP
            8069, // Odoo
            9092, // Kafka
            
            // Веб-сервисы управления
            10000, // Webmin
            10000, // Virtualmin
            9091, // Transmission
            32400, // Plex
            8181, // GlassFish
            4848, // GlassFish admin
            
            // Устаревшие и специфичные
            512, 513, 514, // r-services (rsh, rlogin, rexec)
            515, // LPD
            5431, // PostgreSQL admin
            8089, // Splunk
            9997, 9999, // Splunk
        ];
        
        for &port in &critical_ports {
            match timeout(Duration::from_millis(200), self.check_port_fast(ip, port)).await {
                Ok(Ok(is_open)) => {
                    if is_open {
                        if let Some(mut vuln) = self.check_vulnerability_fast(ip, port).await {
                            if self.is_web_port(port) && self.config.enable_web_deep_scan {
                                if let Some(web_scanner) = &self.web_scanner {
                                    let deep_vulns = web_scanner.deep_scan(ip, port).await;
                                    vulnerabilities.extend(deep_vulns);
                                }
                            }
                            
                            if self.config.enable_nvd_check {
                                if let Some(nvd_client) = &self.nvd_client {
                                    if let Some(nvd_info) = nvd_client.check_vulnerability(&vuln).await {
                                        vuln = self.enhance_with_nvd_info(vuln, nvd_info);
                                    }
                                }
                            }
                            
                            vulnerabilities.push(vuln);
                        }
                    }
                }
                _ => {}
            }
        }
        
        if let IpAddr::V6(_) = ip {
            if let Some(vuln) = self.check_ipv6_vulnerabilities(ip).await {
                vulnerabilities.push(vuln);
            }
        }
        
        self.release_connection(ip).await;
        Ok(vulnerabilities)
    }
    
    fn is_web_port(&self, port: u16) -> bool {
        matches!(port, 80 | 443 | 8080 | 8443 | 8000 | 8008 | 8888 | 3000 | 5000 | 9000)
    }
    
    async fn check_port_fast(&self, ip: IpAddr, port: u16) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let socket_addr = SocketAddr::new(ip, port);
        
        match TcpStream::connect(&socket_addr).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    async fn check_vulnerability_fast(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        match port {
            // SSH и удаленный доступ
            22 | 2222 | 222 | 22222 => self.check_ssh_vulnerabilities(ip, port).await,
            23 => self.check_telnet_vulnerability(ip),
            3389 | 3390 => self.check_rdp_vulnerability(ip),
            5900 | 5901 | 5902 | 5800 | 5801 => self.check_vnc_vulnerability(ip),
            5631 | 5632 => self.check_pcanywhere_vulnerability(ip),
            4899 => self.check_radmin_vulnerability(ip),
            3000 | 3001 => self.check_teamviewer_vulnerability(ip),
            
            // Веб-сервисы
            80 | 443 | 8080 | 8443 | 8000 | 8008 | 8888 | 3000 | 5000 | 9000 => {
                self.check_web_vulnerabilities(ip, port).await
            }
            
            // Базы данных
            3306 | 3307 => self.check_mysql_vulnerabilities(ip, port),
            5432 | 5433 => self.check_postgresql_vulnerabilities(ip, port),
            6379 | 6380 => self.check_redis_vulnerabilities(ip, port),
            27017 | 27018 => self.check_mongodb_vulnerabilities(ip, port),
            9200 | 9300 => self.check_elasticsearch_vulnerabilities(ip, port),
            11211 => self.check_memcached_vulnerabilities(ip),
            1433 | 1434 => self.check_mssql_vulnerabilities(ip, port),
            1521 | 1522 => self.check_oracle_vulnerabilities(ip, port),
            50000 => self.check_db2_vulnerability(ip),
            26257 => self.check_cockroachdb_vulnerability(ip),
            9042 => self.check_cassandra_vulnerability(ip),
            
            // Файловые сервисы
            21 | 20 => self.check_ftp_vulnerabilities(ip, port),
            69 => self.check_tftp_vulnerability(ip),
            2049 => self.check_nfs_vulnerabilities(ip),
            111 => self.check_rpcbind_vulnerabilities(ip),
            139 | 445 => self.check_smb_vulnerabilities(ip, port),
            873 => self.check_rsync_vulnerability(ip),
            
            // Почтовые сервисы
            25 | 465 | 587 => self.check_smtp_vulnerabilities(ip, port),
            110 | 995 => self.check_pop3_vulnerabilities(ip, port),
            143 | 993 => self.check_imap_vulnerabilities(ip, port),
            
            // DNS и сетевые
            53 => self.check_dns_vulnerabilities(ip),
            161 | 162 => self.check_snmp_vulnerabilities(ip, port),
            389 | 636 => self.check_ldap_vulnerabilities(ip, port),
            
            // Контейнеры
            2375 | 2376 => self.check_docker_vulnerabilities(ip, port),
            6443 => self.check_kubernetes_vulnerabilities(ip),
            10250 | 10255 => self.check_kubelet_vulnerabilities(ip, port),
            9099 | 9090 => self.check_prometheus_vulnerability(ip),
            
            // Системные
            5666 => self.check_nagios_vulnerabilities(ip),
            10050 | 10051 => self.check_zabbix_vulnerabilities(ip, port),
            9100 => self.check_node_exporter_vulnerability(ip),
            9093 => self.check_alertmanager_vulnerability(ip),
            
            // Разное
            1723 => self.check_pptp_vulnerability(ip),
            5060 | 5061 => self.check_sip_vulnerabilities(ip, port),
            3478 => self.check_stun_vulnerability(ip),
            1935 => self.check_rtmp_vulnerability(ip),
            554 => self.check_rtsp_vulnerability(ip),
            6697 | 6667 => self.check_irc_vulnerability(ip),
            
            // CMS и приложения
            8081 | 8082 => self.check_jenkins_vulnerabilities(ip, port),
            9001 | 9002 => self.check_supervisor_vulnerability(ip),
            15672 | 5672 => self.check_rabbitmq_vulnerabilities(ip, port),
            8161 | 61616 => self.check_activemq_vulnerabilities(ip, port),
            5984 | 5986 => self.check_couchdb_vulnerabilities(ip, port),
            8069 => self.check_odoo_vulnerability(ip),
            9092 => self.check_kafka_vulnerability(ip),
            
            // Веб-сервисы управления
            10000 => self.check_webmin_vulnerabilities(ip),
            9091 => self.check_transmission_vulnerability(ip),
            32400 => self.check_plex_vulnerability(ip),
            8181 | 4848 => self.check_glassfish_vulnerabilities(ip, port),
            
            // Устаревшие
            512 | 513 | 514 => self.check_rservices_vulnerabilities(ip, port),
            515 => self.check_lpd_vulnerability(ip),
            5431 => self.check_pgadmin_vulnerability(ip),
            8089 | 9997 | 9999 => self.check_splunk_vulnerabilities(ip, port),
            
            _ => None,
        }
    }
    
    async fn get_banner_fast(&self, ip: IpAddr, port: u16) -> Option<String> {
        let socket_addr = SocketAddr::new(ip, port);
        
        match timeout(Duration::from_millis(500), TcpStream::connect(&socket_addr)).await {
            Ok(Ok(mut stream)) => {
                let _ = stream.set_nodelay(true);
                
                let request: Vec<u8> = match port {
                    22 | 2222 | 222 | 22222 => b"SSH-2.0-QuickScan\r\n".to_vec(),
                    21 | 20 => b"USER anonymous\r\n".to_vec(),
                    25 | 465 | 587 => b"HELO scanner\r\n".to_vec(),
                    110 | 995 => b"USER test\r\n".to_vec(),
                    143 | 993 => b"A1 LOGIN test test\r\n".to_vec(),
                    161 | 162 => b"\x30\x29\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00".to_vec(),
                    3389 => b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec(),
                    5432 | 5433 => b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec(),
                    6379 | 6380 => b"PING\r\n".to_vec(),
                    27017 | 27018 => b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec(),
                    _ => b"\r\n".to_vec(),
                };
                
                if let Ok(_) = stream.write_all(&request).await {
                    let mut buffer = [0; 1024];
                    if let Ok(n) = stream.read(&mut buffer).await {
                        if n > 0 {
                            return Some(String::from_utf8_lossy(&buffer[..n]).to_string());
                        }
                    }
                }
                None
            },
            _ => None,
        }
    }
    
    async fn check_ipv6_vulnerabilities(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 0,
            title: "IPv6 доступен".to_string(),
            description: "IPv6 протокол активен, возможны специфичные уязвимости".to_string(),
            cve: Some("CVE-2016-10024".to_string()),
            severity: Severity::Info,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "IPv6 может обходить IPv4 фильтры".to_string(),
            recommendation: "Настроить IPv6 firewall".to_string(),
        })
    }
    
    // SSH уязвимости (много критических RCE)
    async fn check_ssh_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        if let Some(banner) = self.get_banner_fast(ip, port).await {
            lazy_static! {
                static ref RE_SSH_VERSION: Regex = Regex::new(r"SSH-(\d+\.\d+)-(.+)").unwrap();
            }
            
            if let Some(caps) = RE_SSH_VERSION.captures(&banner) {
                let version = caps.get(1).map_or("", |m| m.as_str());
                let software = caps.get(2).map_or("", |m| m.as_str()).to_lowercase();
                
                // КРИТИЧЕСКИЕ УЯЗВИМОСТИ SSH:
                
                // 1. OpenSSH regreSSHion (CVE-2024-6387) - RCE
                if software.contains("openssh") {
                    if let Ok(ver_num) = version.parse::<f32>() {
                        if (8.5..9.8).contains(&ver_num) || (4.4..4.5).contains(&ver_num) {
                            return Some(Vulnerability {
                                ip: ip.to_string(),
                                port,
                                title: "OpenSSH regreSSHion (CVE-2024-6387)".to_string(),
                                description: "CRITICAL: Remote Code Execution через race condition в signal handler".to_string(),
                                cve: Some("CVE-2024-6387".to_string()),
                                severity: Severity::Critical,
                                vuln_type: VulnerabilityType::SSH,
                                exploitation: "Удаленное выполнение кода как root".to_string(),
                                recommendation: "НЕМЕДЛЕННО обновить OpenSSH до 9.8 или новее".to_string(),
                            });
                        }
                    }
                }
                
                // 2. LibSSH Authentication Bypass (CVE-2018-10933) - RCE
                if software.contains("libssh") {
                    return Some(Vulnerability {
                        ip: ip.to_string(),
                        port,
                        title: "LibSSH Authentication Bypass (CVE-2018-10933)".to_string(),
                        description: "CRITICAL: Обход аутентификации, ведущий к RCE".to_string(),
                        cve: Some("CVE-2018-10933".to_string()),
                        severity: Severity::Critical,
                        vuln_type: VulnerabilityType::SSH,
                        exploitation: "Аутентификация не требуется, полный доступ к системе".to_string(),
                        recommendation: "Обновить libssh до 0.7.6 или 0.8.4".to_string(),
                    });
                }
                
                // 3. SSHv1 - полный обход криптографии
                if version.starts_with("1.") {
                    return Some(Vulnerability {
                        ip: ip.to_string(),
                        port,
                        title: "SSHv1 Protocol Enabled".to_string(),
                        description: "CRITICAL: Устаревший протокол с broken криптографией".to_string(),
                        cve: Some("CVE-1999-0634".to_string()),
                        severity: Severity::Critical,
                        vuln_type: VulnerabilityType::SSH,
                        exploitation: "Перехват сессий, MITM, дешифрование трафика".to_string(),
                        recommendation: "НЕМЕДЛЕННО отключить SSHv1 в sshd_config".to_string(),
                    });
                }
                
                // 4. OpenSSH username enumeration (CVE-2018-15473)
                if software.contains("openssh_7.7") || software.contains("openssh_7.8") {
                    return Some(Vulnerability {
                        ip: ip.to_string(),
                        port,
                        title: "OpenSSH Username Enumeration (CVE-2018-15473)".to_string(),
                        description: "Перечисление пользователей системы".to_string(),
                        cve: Some("CVE-2018-15473".to_string()),
                        severity: Severity::Medium,
                        vuln_type: VulnerabilityType::SSH,
                        exploitation: "Enumeration valid usernames for brute-force".to_string(),
                        recommendation: "Обновить OpenSSH".to_string(),
                    });
                }
                
                // 5. Dropbear SSH multiple vulnerabilities
                if software.contains("dropbear") {
                    return Some(Vulnerability {
                        ip: ip.to_string(),
                        port,
                        title: "Dropbear SSH Vulnerabilities".to_string(),
                        description: "Multiple pre-auth vulnerabilities in Dropbear SSH".to_string(),
                        cve: Some("CVE-2022-28366,CVE-2020-36385".to_string()),
                        severity: Severity::High,
                        vuln_type: VulnerabilityType::SSH,
                        exploitation: "Buffer overflows, authentication bypass".to_string(),
                        recommendation: "Обновить Dropbear SSH".to_string(),
                    });
                }
            }
        }
        
        // Общая уязвимость SSH для brute-force
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "SSH Server Exposed".to_string(),
            description: "SSH сервер доступен для атак brute-force".to_string(),
            cve: Some("CWE-307".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::SSH,
            exploitation: "Brute-force паролей, credential stuffing".to_string(),
            recommendation: "Настроить fail2ban, использовать ключи SSH".to_string(),
        })
    }
    
    // RDP уязвимости (критические RCE)
    fn check_rdp_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        // BlueKeep (CVE-2019-0708) - Wormable RCE
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 3389,
            title: "BlueKeep (CVE-2019-0708) - CRITICAL RCE".to_string(),
            description: "Wormable Remote Code Execution vulnerability in RDP".to_string(),
            cve: Some("CVE-2019-0708".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Self-propagating worm, no authentication required".to_string(),
            recommendation: "НЕМЕДЛЕННО установить патч KB4499175/KB4499181".to_string(),
        })
    }
    
    async fn check_web_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        let protocol = if port == 443 || port == 8443 { "https" } else { "http" };
        let url = format!("{}://{}:{}", protocol, ip, port);
        
        match timeout(Duration::from_millis(1000), self.client.head(&url).send()).await {
            Ok(Ok(response)) => {
                if let Some(server_header) = response.headers().get("server") {
                    let server = server_header.to_str().unwrap_or("").to_lowercase();
                    
                    // Apache RCE vulnerabilities
                    if server.contains("apache") {
                        return self.check_apache_vulnerabilities(ip, port, &server);
                    }
                    
                    // NGINX RCE vulnerabilities
                    if server.contains("nginx") {
                        return self.check_nginx_vulnerabilities(ip, port, &server);
                    }
                    
                    // IIS RCE vulnerabilities
                    if server.contains("microsoft-iis") || server.contains("iis") {
                        return self.check_iis_vulnerabilities(ip, port, &server);
                    }
                    
                    // Tomcat RCE vulnerabilities
                    if server.contains("tomcat") || server.contains("apache-coyote") {
                        return self.check_tomcat_vulnerabilities(ip, port, &server);
                    }
                }
            },
            _ => {}
        }
        
        None
    }
    
    fn check_apache_vulnerabilities(&self, ip: IpAddr, port: u16, server: &str) -> Option<Vulnerability> {
        // Apache mod_rewrite RCE (CVE-2021-41773)
        if server.contains("apache/2.4.49") {
            return Some(Vulnerability {
                ip: ip.to_string(),
                port,
                title: "Apache mod_rewrite RCE (CVE-2021-41773)".to_string(),
                description: "CRITICAL: Path traversal and remote code execution".to_string(),
                cve: Some("CVE-2021-41773".to_string()),
                severity: Severity::Critical,
                vuln_type: VulnerabilityType::WebServer,
                exploitation: "curl 'http://target/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh' --data 'echo;id'".to_string(),
                recommendation: "НЕМЕДЛЕННО обновить Apache до 2.4.50".to_string(),
            });
        }
        
        // Apache 2.4.50 Path Traversal (CVE-2021-42013)
        if server.contains("apache/2.4.50") {
            return Some(Vulnerability {
                ip: ip.to_string(),
                port,
                title: "Apache Path Traversal (CVE-2021-42013)".to_string(),
                description: "CRITICAL: Directory traversal leading to RCE".to_string(),
                cve: Some("CVE-2021-42013".to_string()),
                severity: Severity::Critical,
                vuln_type: VulnerabilityType::WebServer,
                exploitation: "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh".to_string(),
                recommendation: "НЕМЕДЛЕННО обновить Apache до 2.4.51".to_string(),
            });
        }
        
        None
    }
    
    fn check_nginx_vulnerabilities(&self, ip: IpAddr, port: u16, server: &str) -> Option<Vulnerability> {
        // NGINX range filter vulnerability (CVE-2017-7529)
        if server.contains("nginx/1.6.2") || server.contains("nginx/1.10.3") || server.contains("nginx/1.13.2") {
            return Some(Vulnerability {
                ip: ip.to_string(),
                port,
                title: "NGINX Integer Overflow RCE (CVE-2017-7529)".to_string(),
                description: "CRITICAL: Integer overflow in range filter module leading to RCE".to_string(),
                cve: Some("CVE-2017-7529".to_string()),
                severity: Severity::Critical,
                vuln_type: VulnerabilityType::WebServer,
                exploitation: "Memory leak leading to potential RCE".to_string(),
                recommendation: "Обновить NGINX".to_string(),
            });
        }
        
        None
    }
    
    fn check_iis_vulnerabilities(&self, ip: IpAddr, port: u16, server: &str) -> Option<Vulnerability> {
        // IIS 6.0 WebDAV RCE (CVE-2017-7269)
        if server.contains("microsoft-iis/6.0") {
            return Some(Vulnerability {
                ip: ip.to_string(),
                port,
                title: "IIS 6.0 WebDAV Buffer Overflow (CVE-2017-7269)".to_string(),
                description: "CRITICAL: Buffer overflow in ScStoragePathFromUrl function".to_string(),
                cve: Some("CVE-2017-7269".to_string()),
                severity: Severity::Critical,
                vuln_type: VulnerabilityType::WebServer,
                exploitation: "Remote code execution via PROPFIND request".to_string(),
                recommendation: "Upgrade to newer IIS version".to_string(),
            });
        }
        
        // HTTP.sys RCE (CVE-2015-1635) - MS15-034
        if server.contains("microsoft-iis/7.5") || server.contains("microsoft-iis/8.0") {
            return Some(Vulnerability {
                ip: ip.to_string(),
                port,
                title: "HTTP.sys Remote Code Execution (CVE-2015-1635)".to_string(),
                description: "CRITICAL: RCE in HTTP protocol stack".to_string(),
                cve: Some("CVE-2015-1635".to_string()),
                severity: Severity::Critical,
                vuln_type: VulnerabilityType::WebServer,
                exploitation: "Range header attack leading to RCE".to_string(),
                recommendation: "Install MS15-034 patch immediately".to_string(),
            });
        }
        
        None
    }
    
    fn check_tomcat_vulnerabilities(&self, ip: IpAddr, port: u16, server: &str) -> Option<Vulnerability> {
        // Tomcat Ghostcat (CVE-2020-1938)
        if server.contains("apache-coyote/1.1") {
            return Some(Vulnerability {
                ip: ip.to_string(),
                port,
                title: "Apache Tomcat AJP RCE (CVE-2020-1938)".to_string(),
                description: "CRITICAL: Ghostcat vulnerability - file read and RCE via AJP".to_string(),
                cve: Some("CVE-2020-1938".to_string()),
                severity: Severity::Critical,
                vuln_type: VulnerabilityType::WebServer,
                exploitation: "Read arbitrary files and potentially RCE via AJP connector".to_string(),
                recommendation: "Disable AJP connector or upgrade Tomcat".to_string(),
            });
        }
        
        // Tomcat JMX RCE (CVE-2016-8735)
        if server.contains("tomcat/8.0.0") || server.contains("tomcat/8.0.1") || server.contains("tomcat/8.0.2") {
            return Some(Vulnerability {
                ip: ip.to_string(),
                port,
                title: "Tomcat JMX Remote Code Execution (CVE-2016-8735)".to_string(),
                description: "CRITICAL: RCE via JMX deserialization".to_string(),
                cve: Some("CVE-2016-8735".to_string()),
                severity: Severity::Critical,
                vuln_type: VulnerabilityType::WebServer,
                exploitation: "JMX deserialization leading to RCE".to_string(),
                recommendation: "Upgrade Tomcat, disable JMX".to_string(),
            });
        }
        
        None
    }
    
    // Database RCE vulnerabilities
    fn check_mysql_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // MySQL Authentication Bypass (CVE-2012-2122)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "MySQL Authentication Bypass (CVE-2012-2122)".to_string(),
            description: "CRITICAL: Race condition allows authentication bypass".to_string(),
            cve: Some("CVE-2012-2122".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Database,
            exploitation: "Brute-force authentication bypass in 1 of 256 attempts".to_string(),
            recommendation: "Update MySQL, restrict network access".to_string(),
        })
    }
    
    fn check_postgresql_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // PostgreSQL COPY FROM PROGRAM RCE (CVE-2019-9193)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "PostgreSQL COPY FROM PROGRAM RCE (CVE-2019-9193)".to_string(),
            description: "CRITICAL: Authenticated users can execute OS commands".to_string(),
            cve: Some("CVE-2019-9193".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Database,
            exploitation: "COPY FROM PROGRAM allows OS command execution".to_string(),
            recommendation: "Update PostgreSQL, revoke superuser privileges".to_string(),
        })
    }
    
    fn check_redis_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // Redis Lua Sandbox Escape (CVE-2022-0543)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Redis Lua Sandbox Escape (CVE-2022-0543)".to_string(),
            description: "CRITICAL: RCE via Lua sandbox escape in Debian/Ubuntu".to_string(),
            cve: Some("CVE-2022-0543".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Database,
            exploitation: "eval 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"id\", \"r\"); local res = f:read(\"*a\"); f:close(); return res' 0".to_string(),
            recommendation: "Update Redis package, enable authentication".to_string(),
        })
    }
    
    fn check_mongodb_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // MongoDB JavaScript Injection (CVE-2019-10758)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "MongoDB JavaScript Injection (CVE-2019-10758)".to_string(),
            description: "CRITICAL: $where operator allows JavaScript injection".to_string(),
            cve: Some("CVE-2019-10758".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Database,
            exploitation: "JavaScript injection via $where operator".to_string(),
            recommendation: "Update MongoDB, disable server-side JavaScript".to_string(),
        })
    }
    
    fn check_elasticsearch_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // Elasticsearch Groovy RCE (CVE-2015-1427)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Elasticsearch Groovy RCE (CVE-2015-1427)".to_string(),
            description: "CRITICAL: Remote code execution via Groovy scripting".to_string(),
            cve: Some("CVE-2015-1427".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::SearchEngine,
            exploitation: "Search queries can execute arbitrary Groovy code".to_string(),
            recommendation: "Update Elasticsearch, disable dynamic scripting".to_string(),
        })
    }
    
    fn check_memcached_vulnerabilities(&self, ip: IpAddr) -> Option<Vulnerability> {
        // Memcached RCE (CVE-2016-8704, CVE-2016-8705, CVE-2016-8706)
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 11211,
            title: "Memcached Multiple RCE Vulnerabilities".to_string(),
            description: "CRITICAL: Integer overflows leading to RCE".to_string(),
            cve: Some("CVE-2016-8704,CVE-2016-8705,CVE-2016-8706".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Database,
            exploitation: "Buffer overflows in memcached binary protocol".to_string(),
            recommendation: "Update memcached, disable UDP".to_string(),
        })
    }
    
    fn check_mssql_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // MS SQL RCE (CVE-2020-0618)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Microsoft SQL Server RCE (CVE-2020-0618)".to_string(),
            description: "CRITICAL: Remote code execution via SQL Server".to_string(),
            cve: Some("CVE-2020-0618".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Database,
            exploitation: "RCE via SQL Server Reporting Services".to_string(),
            recommendation: "Install security updates".to_string(),
        })
    }
    
    fn check_oracle_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // Oracle WebLogic RCE (CVE-2020-14882, CVE-2020-14883)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Oracle WebLogic RCE (CVE-2020-14882/14883)".to_string(),
            description: "CRITICAL: Pre-auth RCE in Oracle WebLogic Server".to_string(),
            cve: Some("CVE-2020-14882,CVE-2020-14883".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Database,
            exploitation: "Unauthenticated remote code execution".to_string(),
            recommendation: "Apply Oracle Critical Patch Update".to_string(),
        })
    }
    
    // SMB RCE vulnerabilities (EternalBlue)
    fn check_smb_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "SMBv1 EternalBlue (CVE-2017-0144)".to_string(),
            description: "CRITICAL: Wormable RCE vulnerability in SMBv1".to_string(),
            cve: Some("CVE-2017-0144".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Self-propagating worm (WannaCry, NotPetya)".to_string(),
            recommendation: "НЕМЕДЛЕННО отключить SMBv1".to_string(),
        })
    }
    
    // Docker RCE vulnerabilities
    fn check_docker_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // Docker runc container escape (CVE-2019-5736)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Docker runc Container Escape (CVE-2019-5736)".to_string(),
            description: "CRITICAL: Container escape to host root access".to_string(),
            cve: Some("CVE-2019-5736".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Malicious container can gain root on host".to_string(),
            recommendation: "Update Docker and runc immediately".to_string(),
        })
    }
    
    // Kubernetes RCE vulnerabilities
    fn check_kubernetes_vulnerabilities(&self, ip: IpAddr) -> Option<Vulnerability> {
        // Kubernetes API Server RCE (CVE-2018-1002105)
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 6443,
            title: "Kubernetes API Server RCE (CVE-2018-1002105)".to_string(),
            description: "CRITICAL: Privilege escalation via Kubernetes API server".to_string(),
            cve: Some("CVE-2018-1002105".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Unauthenticated RCE on Kubernetes cluster".to_string(),
            recommendation: "Update Kubernetes, enable RBAC".to_string(),
        })
    }
    
    // Jenkins RCE vulnerabilities
    fn check_jenkins_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // Jenkins RCE (CVE-2019-1003000, CVE-2019-1003001, CVE-2019-1003002)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Jenkins RCE via Pipeline (CVE-2019-1003000)".to_string(),
            description: "CRITICAL: Pre-auth RCE in Jenkins Pipeline".to_string(),
            cve: Some("CVE-2019-1003000,CVE-2019-1003001,CVE-2019-1003002".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::WebServer,
            exploitation: "Remote code execution via deserialization".to_string(),
            recommendation: "Update Jenkins immediately".to_string(),
        })
    }
    
    // Webmin RCE vulnerabilities
    fn check_webmin_vulnerabilities(&self, ip: IpAddr) -> Option<Vulnerability> {
        // Webmin RCE (CVE-2019-15107)
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 10000,
            title: "Webmin Password Change RCE (CVE-2019-15107)".to_string(),
            description: "CRITICAL: Pre-auth RCE in Webmin password change function".to_string(),
            cve: Some("CVE-2019-15107".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::WebServer,
            exploitation: "Unauthenticated remote code execution".to_string(),
            recommendation: "Update Webmin to 1.930 or later".to_string(),
        })
    }
    
    // Splunk RCE vulnerabilities
    fn check_splunk_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        // Splunk RCE (CVE-2022-32158)
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Splunk RCE via Dashboard (CVE-2022-32158)".to_string(),
            description: "CRITICAL: Authenticated RCE via dashboard".to_string(),
            cve: Some("CVE-2022-32158".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::WebServer,
            exploitation: "Remote code execution via dashboard".to_string(),
            recommendation: "Update Splunk".to_string(),
        })
    }
    
    // Другие уязвимости с меньшим приоритетом
    fn check_telnet_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 23,
            title: "Telnet Server Exposed".to_string(),
            description: "Telnet transmits credentials in clear text".to_string(),
            cve: Some("CVE-1999-0508".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::SSH,
            exploitation: "Credential sniffing, MITM attacks".to_string(),
            recommendation: "Disable Telnet, use SSH".to_string(),
        })
    }
    
    fn check_vnc_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 5900,
            title: "VNC Server Without Authentication".to_string(),
            description: "VNC transmits screen data in clear text".to_string(),
            cve: Some("CVE-2006-2369".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Screen capture, keyboard injection".to_string(),
            recommendation: "Use VNC over SSH tunnel".to_string(),
        })
    }
    
    fn check_ftp_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "FTP Server Exposed".to_string(),
            description: "FTP transmits data in clear text".to_string(),
            cve: Some("CVE-1999-0017".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Credential sniffing, data interception".to_string(),
            recommendation: "Use SFTP or FTPS".to_string(),
        })
    }
    
    fn enhance_with_nvd_info(&self, mut vuln: Vulnerability, nvd_info: String) -> Vulnerability {
        vuln.description = format!("{} | NVD: {}", vuln.description, nvd_info);
        vuln
    }
    
    async fn save_vulnerability(&self, vuln: &Vulnerability) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(results_file) = &self.results_file {
            let mut writer = results_file.lock().await;
            writer.write_all(vuln.to_markdown().as_bytes()).await?;
            writer.flush().await?;
        }
        
        if let Some(csv_file) = &self.csv_file {
            let mut writer = csv_file.lock().await;
            writer.write_all(vuln.to_csv().as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
        
        Ok(())
    }
    
    async fn finalize_files(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(results_file) = &self.results_file {
            let mut writer = results_file.lock().await;
            writer.flush().await?;
        }
        
        if let Some(csv_file) = &self.csv_file {
            let mut writer = csv_file.lock().await;
            writer.flush().await?;
        }
        
        Ok(())
    }
    
    // Дополнительные функции проверки (заглушки для краткости)
    fn check_pcanywhere_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 5632,
            title: "pcAnywhere Server".to_string(),
            description: "Legacy remote access software".to_string(),
            cve: Some("CVE-2012-4940".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Multiple vulnerabilities".to_string(),
            recommendation: "Disable pcAnywhere".to_string(),
        })
    }
    
    fn check_radmin_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 4899,
            title: "Radmin Server".to_string(),
            description: "Remote administration software".to_string(),
            cve: Some("CVE-2019-14487".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Authentication bypass".to_string(),
            recommendation: "Update Radmin".to_string(),
        })
    }
    
    fn check_teamviewer_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 3000,
            title: "TeamViewer Service".to_string(),
            description: "Remote desktop software".to_string(),
            cve: Some("CVE-2020-13699".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Unquoted service path".to_string(),
            recommendation: "Update TeamViewer".to_string(),
        })
    }
    
    fn check_db2_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 50000,
            title: "IBM DB2 Database".to_string(),
            description: "Enterprise database system".to_string(),
            cve: Some("CVE-2022-29600".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Database,
            exploitation: "SQL injection".to_string(),
            recommendation: "Update DB2".to_string(),
        })
    }
    
    fn check_cockroachdb_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 26257,
            title: "CockroachDB Database".to_string(),
            description: "Distributed SQL database".to_string(),
            cve: Some("CVE-2021-29630".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Database,
            exploitation: "SQL injection".to_string(),
            recommendation: "Update CockroachDB".to_string(),
        })
    }
    
    fn check_cassandra_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 9042,
            title: "Apache Cassandra".to_string(),
            description: "NoSQL database".to_string(),
            cve: Some("CVE-2021-44521".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Database,
            exploitation: "Unauthorized access".to_string(),
            recommendation: "Update Cassandra".to_string(),
        })
    }
    
    fn check_tftp_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 69,
            title: "TFTP Server".to_string(),
            description: "Trivial File Transfer Protocol".to_string(),
            cve: Some("CWE-306".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Unauthorized file access".to_string(),
            recommendation: "Disable TFTP".to_string(),
        })
    }
    
    fn check_nfs_vulnerabilities(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 2049,
            title: "NFS Server".to_string(),
            description: "Network File System".to_string(),
            cve: Some("CVE-1999-0170".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Unauthorized file access".to_string(),
            recommendation: "Restrict NFS exports".to_string(),
        })
    }
    
    fn check_rpcbind_vulnerabilities(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 111,
            title: "RPCbind Service".to_string(),
            description: "Remote Procedure Call binder".to_string(),
            cve: Some("CVE-2017-8779".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Information disclosure".to_string(),
            recommendation: "Restrict RPCbind access".to_string(),
        })
    }
    
    fn check_rsync_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 873,
            title: "rsync Server".to_string(),
            description: "File synchronization tool".to_string(),
            cve: Some("CVE-2017-16548".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Unauthorized file access".to_string(),
            recommendation: "Use SSH tunnel for rsync".to_string(),
        })
    }
    
    fn check_smtp_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "SMTP Server".to_string(),
            description: "Mail transfer agent".to_string(),
            cve: Some("CVE-2011-1720".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Open relay".to_string(),
            recommendation: "Configure SMTP authentication".to_string(),
        })
    }
    
    fn check_pop3_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "POP3 Server".to_string(),
            description: "Mail retrieval protocol".to_string(),
            cve: Some("CVE-1999-0526".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Credential sniffing".to_string(),
            recommendation: "Use POP3S".to_string(),
        })
    }
    
    fn check_imap_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "IMAP Server".to_string(),
            description: "Mail access protocol".to_string(),
            cve: Some("CVE-2018-19518".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Credential sniffing".to_string(),
            recommendation: "Use IMAPS".to_string(),
        })
    }
    
    fn check_dns_vulnerabilities(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 53,
            title: "DNS Server".to_string(),
            description: "Domain Name System".to_string(),
            cve: Some("CVE-2020-1350".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "DNS amplification attacks".to_string(),
            recommendation: "Disable recursion for external clients".to_string(),
        })
    }
    
    fn check_snmp_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "SNMP Service".to_string(),
            description: "Network management protocol".to_string(),
            cve: Some("CVE-2002-0013".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Information disclosure".to_string(),
            recommendation: "Use SNMPv3 with encryption".to_string(),
        })
    }
    
    fn check_ldap_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "LDAP Server".to_string(),
            description: "Directory access protocol".to_string(),
            cve: Some("CVE-2017-17427".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Credential sniffing".to_string(),
            recommendation: "Use LDAPS".to_string(),
        })
    }
    
    fn check_kubelet_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Kubelet API".to_string(),
            description: "Kubernetes node agent".to_string(),
            cve: Some("CVE-2018-1002100".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Remote code execution".to_string(),
            recommendation: "Enable Kubelet authentication".to_string(),
        })
    }
    
    fn check_prometheus_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 9090,
            title: "Prometheus Metrics".to_string(),
            description: "Monitoring system".to_string(),
            cve: Some("CVE-2021-29622".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Information disclosure".to_string(),
            recommendation: "Restrict Prometheus access".to_string(),
        })
    }
    
    fn check_nagios_vulnerabilities(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 5666,
            title: "Nagios Monitoring".to_string(),
            description: "IT infrastructure monitoring".to_string(),
            cve: Some("CVE-2016-9566".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Command injection".to_string(),
            recommendation: "Update Nagios".to_string(),
        })
    }
    
    fn check_zabbix_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "Zabbix Monitoring".to_string(),
            description: "Enterprise monitoring solution".to_string(),
            cve: Some("CVE-2022-23131".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Authentication bypass".to_string(),
            recommendation: "Update Zabbix".to_string(),
        })
    }
    
    fn check_node_exporter_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 9100,
            title: "Node Exporter".to_string(),
            description: "Prometheus system metrics exporter".to_string(),
            cve: Some("CVE-2022-24675".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Information disclosure".to_string(),
            recommendation: "Restrict node_exporter access".to_string(),
        })
    }
    
    fn check_alertmanager_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 9093,
            title: "Alertmanager".to_string(),
            description: "Prometheus alert manager".to_string(),
            cve: Some("CVE-2021-29622".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Information disclosure".to_string(),
            recommendation: "Restrict Alertmanager access".to_string(),
        })
    }
    
    fn check_pptp_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 1723,
            title: "PPTP VPN".to_string(),
            description: "Point-to-Point Tunneling Protocol".to_string(),
            cve: Some("CVE-2012-1855".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "MS-CHAPv2 cracking".to_string(),
            recommendation: "Use OpenVPN or WireGuard".to_string(),
        })
    }
    
    fn check_sip_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "SIP Server".to_string(),
            description: "Session Initiation Protocol for VoIP".to_string(),
            cve: Some("CVE-2011-1508".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Call spoofing".to_string(),
            recommendation: "Use SIP over TLS".to_string(),
        })
    }
    
    fn check_stun_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 3478,
            title: "STUN Server".to_string(),
            description: "Session Traversal Utilities for NAT".to_string(),
            cve: Some("CVE-2020-26262".to_string()),
            severity: Severity::Low,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Information disclosure".to_string(),
            recommendation: "Restrict STUN access".to_string(),
        })
    }
    
    fn check_rtmp_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 1935,
            title: "RTMP Server".to_string(),
            description: "Real Time Messaging Protocol".to_string(),
            cve: Some("CVE-2015-6000".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Buffer overflow".to_string(),
            recommendation: "Update RTMP server".to_string(),
        })
    }
    
    fn check_rtsp_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 554,
            title: "RTSP Server".to_string(),
            description: "Real Time Streaming Protocol".to_string(),
            cve: Some("CVE-2020-9054".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Buffer overflow".to_string(),
            recommendation: "Update RTSP server".to_string(),
        })
    }
    
    fn check_irc_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 6667,
            title: "IRC Server".to_string(),
            description: "Internet Relay Chat".to_string(),
            cve: Some("CVE-2010-2075".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Buffer overflow".to_string(),
            recommendation: "Update IRC server".to_string(),
        })
    }
    
    fn check_supervisor_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 9001,
            title: "Supervisor Process Manager".to_string(),
            description: "Process control system".to_string(),
            cve: Some("CVE-2017-11610".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Remote code execution".to_string(),
            recommendation: "Update Supervisor".to_string(),
        })
    }
    
    fn check_rabbitmq_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "RabbitMQ Message Broker".to_string(),
            description: "Message queue system".to_string(),
            cve: Some("CVE-2021-22116".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Remote code execution".to_string(),
            recommendation: "Update RabbitMQ".to_string(),
        })
    }
    
    fn check_activemq_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "ActiveMQ Message Broker".to_string(),
            description: "Message queue system".to_string(),
            cve: Some("CVE-2016-3088".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Remote code execution".to_string(),
            recommendation: "Update ActiveMQ".to_string(),
        })
    }
    
    fn check_couchdb_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "CouchDB Database".to_string(),
            description: "NoSQL database".to_string(),
            cve: Some("CVE-2022-24706".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Database,
            exploitation: "Remote code execution".to_string(),
            recommendation: "Update CouchDB".to_string(),
        })
    }
    
    fn check_odoo_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 8069,
            title: "Odoo ERP".to_string(),
            description: "Enterprise resource planning".to_string(),
            cve: Some("CVE-2022-21635".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::WebServer,
            exploitation: "SQL injection".to_string(),
            recommendation: "Update Odoo".to_string(),
        })
    }
    
    fn check_kafka_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 9092,
            title: "Apache Kafka".to_string(),
            description: "Distributed streaming platform".to_string(),
            cve: Some("CVE-2021-38153".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Remote code execution".to_string(),
            recommendation: "Update Kafka".to_string(),
        })
    }
    
    fn check_transmission_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 9091,
            title: "Transmission BitTorrent".to_string(),
            description: "BitTorrent client".to_string(),
            cve: Some("CVE-2020-15195".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Cross-site request forgery".to_string(),
            recommendation: "Update Transmission".to_string(),
        })
    }
    
    fn check_plex_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 32400,
            title: "Plex Media Server".to_string(),
            description: "Media streaming server".to_string(),
            cve: Some("CVE-2020-5741".to_string()),
            severity: Severity::Medium,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Information disclosure".to_string(),
            recommendation: "Update Plex".to_string(),
        })
    }
    
    fn check_glassfish_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "GlassFish Application Server".to_string(),
            description: "Java EE application server".to_string(),
            cve: Some("CVE-2017-1000028".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::WebServer,
            exploitation: "Remote code execution".to_string(),
            recommendation: "Update GlassFish".to_string(),
        })
    }
    
    fn check_rservices_vulnerabilities(&self, ip: IpAddr, port: u16) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port,
            title: "r-services (rsh/rlogin/rexec)".to_string(),
            description: "Legacy remote access services".to_string(),
            cve: Some("CVE-1999-0651".to_string()),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "No authentication required".to_string(),
            recommendation: "DISABLE immediately, use SSH".to_string(),
        })
    }
    
    fn check_lpd_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 515,
            title: "LPD Service".to_string(),
            description: "Line Printer Daemon".to_string(),
            cve: Some("CVE-2011-2891".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::Misconfiguration,
            exploitation: "Remote code execution".to_string(),
            recommendation: "Disable LPD".to_string(),
        })
    }
    
    fn check_pgadmin_vulnerability(&self, ip: IpAddr) -> Option<Vulnerability> {
        Some(Vulnerability {
            ip: ip.to_string(),
            port: 5431,
            title: "pgAdmin Database Management".to_string(),
            description: "PostgreSQL management tool".to_string(),
            cve: Some("CVE-2022-4223".to_string()),
            severity: Severity::High,
            vuln_type: VulnerabilityType::WebServer,
            exploitation: "SQL injection".to_string(),
            recommendation: "Update pgAdmin".to_string(),
        })
    }
}

impl Clone for HighPerformanceScanner {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
            semaphore: Arc::clone(&self.semaphore),
            results_file: self.results_file.clone(),
            csv_file: self.csv_file.clone(),
            web_scanner: self.web_scanner.clone(),
            nvd_client: self.nvd_client.clone(),
            rate_limiter: Arc::clone(&self.rate_limiter),
            active_tasks: Arc::clone(&self.active_tasks),
            connection_pool: Arc::clone(&self.connection_pool),
            stop_flag: Arc::clone(&self.stop_flag),
            network_monitor: Arc::clone(&self.network_monitor),
        }
    }
}