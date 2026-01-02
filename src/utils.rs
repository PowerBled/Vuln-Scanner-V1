use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use ipnetwork::IpNetwork;
use thiserror::Error;
use colored::Colorize;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("IP parse error: {0}")]
    IpParse(#[from] std::net::AddrParseError),
    #[error("Network parse error: {0}")]
    NetworkParse(#[from] ipnetwork::IpNetworkError),
    #[error("Invalid IP range format: {0}")]
    InvalidRangeFormat(String),
}

pub fn load_ip_ranges(filename: &str) -> Result<Vec<IpNetwork>, ScannerError> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut ranges = Vec::new();
    
    for (_line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Обработка IPv6
        if line.contains(':') {
            // IPv6 CIDR
            if line.contains('/') {
                let network: IpNetwork = line.parse()?;
                ranges.push(network);
            } 
            // IPv6 диапазон
            else if let Some(dash_idx) = line.find('-') {
                let start_str = &line[..dash_idx].trim();
                let end_str = &line[dash_idx + 1..].trim();
                
                let start_ip: IpAddr = start_str.parse()?;
                let end_ip: IpAddr = end_str.parse()?;
                
                if let (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) = (start_ip, end_ip) {
                    // Для IPv6 диапазонов - используем весь диапазон как CIDR
                    // Но ограничиваем размер для производительности
                    let start_u128 = ipv6_to_u128(start_v6);
                    let end_u128 = ipv6_to_u128(end_v6);
                    
                    // Для больших диапазонов IPv6 используем CIDR представление
                    if end_u128 - start_u128 > 1000 {
                        // Если диапазон очень большой, добавляем начальный и конечный IP
                        ranges.push(IpNetwork::new(IpAddr::V6(start_v6), 128)?);
                        ranges.push(IpNetwork::new(IpAddr::V6(end_v6), 128)?);
                    } else {
                        // Для небольших диапазонов добавляем все IP
                        let mut current = start_u128;
                        while current <= end_u128 {
                            let ip = u128_to_ipv6(current);
                            ranges.push(IpNetwork::new(IpAddr::V6(ip), 128)?);
                            current += 1;
                        }
                    }
                }
            }
            // Одиночный IPv6
            else {
                let ip: IpAddr = line.parse()?;
                ranges.push(IpNetwork::new(ip, 128)?);
            }
        }
        // Обработка IPv4
        else {
            // Формат: x.x.x.x-y.y.y.y
            if let Some(dash_idx) = line.find('-') {
                let start_str = &line[..dash_idx].trim();
                let end_str = &line[dash_idx + 1..].trim();
                
                let start_ip: IpAddr = start_str.parse()?;
                let end_ip: IpAddr = end_str.parse()?;
                
                if let (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) = (start_ip, end_ip) {
                    // Эффективное преобразование диапазона в CIDR блоки
                    let cidr_blocks = range_to_cidr_blocks_efficient(start_v4, end_v4);
                    ranges.extend(cidr_blocks);
                }
            } else {
                // Одиночный IP или CIDR
                if line.contains('/') {
                    let network: IpNetwork = line.parse()?;
                    ranges.push(network);
                } else {
                    let ip: IpAddr = line.parse()?;
                    ranges.push(IpNetwork::new(ip, if matches!(ip, IpAddr::V4(_)) { 32 } else { 128 })?);
                }
            }
        }
    }
    
    println!("{} Загружено {} диапазонов IP", "✓".green(), ranges.len());
    
    // Оптимизация: объединяем смежные CIDR блоки
    ranges = merge_cidr_ranges(ranges);
    println!("{} После оптимизации: {} диапазонов", "✓".green(), ranges.len());
    
    Ok(ranges)
}

fn range_to_cidr_blocks_efficient(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpNetwork> {
    let mut blocks = Vec::new();
    let mut current = u32::from(start);
    let end_u32 = u32::from(end);
    
    while current <= end_u32 {
        // Находим максимальный CIDR блок, начинающийся с current
        let mut mask = 32;
        
        // Находим максимальную маску (самый большой блок)
        while mask > 0 {
            let block_size = 1u32 << (32 - mask);
            let block_end = current + block_size - 1;
            
            // Блок должен быть выровнен по границе и помещаться в диапазон
            if (current & (block_size - 1)) == 0 && block_end <= end_u32 {
                break;
            }
            mask -= 1;
        }
        
        // Добавляем найденный блок
        if let Ok(network) = IpNetwork::new(IpAddr::V4(Ipv4Addr::from(current)), mask) {
            blocks.push(network);
        }
        
        // Переходим к следующему блоку
        let block_size = 1u32 << (32 - mask);
        current += block_size;
    }
    
    blocks
}

// Функция для объединения смежных CIDR блоков
fn merge_cidr_ranges(mut ranges: Vec<IpNetwork>) -> Vec<IpNetwork> {
    if ranges.len() <= 1 {
        return ranges;
    }
    
    // Сортируем по начальному адресу
    ranges.sort_by(|a, b| {
        let a_start = match a {
            IpNetwork::V4(net) => u32::from(net.network()) as u128,
            IpNetwork::V6(net) => ipv6_to_u128(net.network()),
        };
        let b_start = match b {
            IpNetwork::V4(net) => u32::from(net.network()) as u128,
            IpNetwork::V6(net) => ipv6_to_u128(net.network()),
        };
        a_start.cmp(&b_start)
    });
    
    let mut merged = Vec::new();
    let mut current = ranges[0];
    
    for next in ranges.into_iter().skip(1) {
        if can_merge(&current, &next) {
            // Попробуем объединить
            if let Some(merged_range) = try_merge_cidr(current, next) {
                current = merged_range;
            } else {
                merged.push(current);
                current = next;
            }
        } else {
            merged.push(current);
            current = next;
        }
    }
    
    merged.push(current);
    merged
}

fn can_merge(a: &IpNetwork, b: &IpNetwork) -> bool {
    match (a, b) {
        (IpNetwork::V4(a_net), IpNetwork::V4(b_net)) => {
            a_net.prefix() == b_net.prefix() && 
            (u32::from(a_net.broadcast()) + 1 == u32::from(b_net.network()) ||
             u32::from(b_net.broadcast()) + 1 == u32::from(a_net.network()))
        }
        _ => false, // Для IPv6 не объединяем для простоты
    }
}

fn try_merge_cidr(a: IpNetwork, b: IpNetwork) -> Option<IpNetwork> {
    match (a, b) {
        (IpNetwork::V4(a_net), IpNetwork::V4(b_net)) => {
            if a_net.prefix() != b_net.prefix() {
                return None;
            }
            
            let a_start = u32::from(a_net.network());
            let a_end = u32::from(a_net.broadcast());
            let b_start = u32::from(b_net.network());
            let b_end = u32::from(b_net.broadcast());
            
            // Проверяем смежность
            if a_end + 1 == b_start {
                let new_prefix = a_net.prefix() - 1;
                if new_prefix >= 0 {
                    // Проверяем, что новый блок включает оба старых
                    let new_network = Ipv4Addr::from(a_start & !(1 << (32 - new_prefix)));
                    if let Ok(new_net) = IpNetwork::new(IpAddr::V4(new_network), new_prefix as u8) {
                        let new_start = match new_net.network() {
                            IpAddr::V4(ip) => u32::from(ip),
                            _ => return None,
                        };
                        let new_end = match new_net.broadcast() {
                            IpAddr::V4(ip) => u32::from(ip),
                            _ => return None,
                        };
                        if new_start <= a_start && new_end >= b_end {
                            return Some(new_net);
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

pub fn count_total_ips(ip_ranges: &[IpNetwork]) -> u64 {
    let mut total = 0u64;
    
    for range in ip_ranges {
        match range {
            IpNetwork::V4(v4_range) => {
                let prefix = v4_range.prefix();
                if prefix == 32 {
                    total += 1;
                } else {
                    // Для больших диапазонов показываем реальное количество
                    let range_total = 2u64.pow(32 - prefix as u32);
                    total += range_total;
                }
            }
            IpNetwork::V6(v6_range) => {
                let prefix = v6_range.prefix();
                if prefix == 128 {
                    total += 1;
                } else {
                    // Ограничиваем IPv6 диапазоны для производительности
                    let range_total = 2u64.pow(128 - prefix as u32);
                    // Для больших IPv6 диапазонов ограничиваем сканирование
                    total += range_total.min(1000);
                }
            }
        }
    }
    
    total
}

// Вспомогательные функции для IPv6
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from(ip)
}

fn u128_to_ipv6(ip_u128: u128) -> Ipv6Addr {
    Ipv6Addr::from(ip_u128)
}

pub fn create_summary_file(vuln_count: usize) -> Result<(), ScannerError> {
    let mut summary = File::create("results/summary.txt")?;
    
    writeln!(summary, "=== Краткая сводка сканирования ===\n")?;
    writeln!(summary, "Найдено уязвимостей: {}\n", vuln_count)?;
    writeln!(summary, "Подробные результаты в файлах:")?;
    writeln!(summary, "  - vulnerabilities.txt: полный отчет в Markdown формате")?;
    writeln!(summary, "  - vulnerabilities.csv: результаты в CSV формате")?;
    writeln!(summary, "  - statistics.txt: статистика сканирования")?;
    writeln!(summary, "  - recommendations.txt: рекомендации по исправлению")?;
    
    Ok(())
}

pub fn save_statistics(duration: Duration, total_ips: u64, vuln_count: usize, ips_per_second: f64) -> Result<(), ScannerError> {
    let mut stats_file = File::create("results/statistics.txt")?;
    
    writeln!(stats_file, "=== Статистика сканирования ===\n")?;
    writeln!(stats_file, "Общее время сканирования: {:.2?}", duration)?;
    writeln!(stats_file, "Просканировано IP-адресов: {}", total_ips)?;
    writeln!(stats_file, "Найдено уязвимостей: {}", vuln_count)?;
    writeln!(stats_file, "Скорость сканирования: {:.2} IP/сек", ips_per_second)?;
    
    if total_ips > 0 {
        writeln!(stats_file, "Процент уязвимых хостов: {:.2}%", (vuln_count as f64 / total_ips as f64 * 100.0))?;
    }
    
    // Сохраняем рекомендации
    save_recommendations()?;
    
    Ok(())
}

fn save_recommendations() -> Result<(), ScannerError> {
    let mut rec_file = File::create("results/recommendations.txt")?;
    
    writeln!(rec_file, "=== Рекомендации по безопасности ===\n")?;
    writeln!(rec_file, "1. Сетевая безопасность:")?;
    writeln!(rec_file, "   - Используйте firewall для ограничения доступа к портам")?;
    writeln!(rec_file, "   - Настройте rate limiting для предотвращения DoS")?;
    writeln!(rec_file, "   - Регулярно обновляйте сетевые сервисы\n")?;
    
    writeln!(rec_file, "2. Веб-безопасность:")?;
    writeln!(rec_file, "   - Настройте security headers (CSP, HSTS, X-Frame-Options)")?;
    writeln!(rec_file, "   - Используйте HTTPS с современными шифрами")?;
    writeln!(rec_file, "   - Отключите листинг директорий\n")?;
    
    writeln!(rec_file, "3. Системная безопасность:")?;
    writeln!(rec_file, "   - Регулярно обновляйте ПО и ядро системы")?;
    writeln!(rec_file, "   - Отключите ненужные службы и порты")?;
    writeln!(rec_file, "   - Используйте минимальные привилегии\n")?;
    
    writeln!(rec_file, "4. Мониторинг:")?;
    writeln!(rec_file, "   - Настройте логирование и мониторинг")?;
    writeln!(rec_file, "   - Регулярно проводите сканирование уязвимостей")?;
    writeln!(rec_file, "   - Используйте системы обнаружения вторжений")?;
    
    Ok(())
}

// Новые функции для измерения пропускной способности сети
#[cfg(target_os = "windows")]
pub fn get_network_interface() -> Option<String> {
    // Для Windows можно использовать netsh или powershell
    use std::process::Command;
    
    if let Ok(output) = Command::new("powershell")
        .args(&["Get-NetAdapter", "|", "Where-Object", "{$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*'}", "|", "Select-Object", "-First", "1", "-ExpandProperty", "Name"])
        .output() {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !output_str.is_empty() {
                return Some(output_str);
            }
        }
    }
    
    None
}

#[cfg(not(target_os = "windows"))]
pub fn get_network_interface() -> Option<String> {
    // Для Linux используем ip или ifconfig
    use std::process::Command;
    
    if let Ok(output) = Command::new("ip").args(&["route", "show", "default"]).output() {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output_str.lines().next() {
                if let Some(iface) = line.split_whitespace().nth(4) {
                    return Some(iface.to_string());
                }
            }
        }
    }
    
    // Fallback на ifconfig
    if let Ok(output) = Command::new("ifconfig").output() {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if !line.starts_with(' ') && !line.is_empty() && line.contains(':') {
                    if let Some(iface) = line.split(':').next() {
                        if iface != "lo" { // Исключаем loopback
                            return Some(iface.to_string());
                        }
                    }
                }
            }
        }
    }
    
    None
}

pub fn estimate_network_capacity() -> (usize, usize) {
    // Базовая оценка пропускной способности
    // Возвращает (параллельные подключения, запросов в секунду)
    
    #[cfg(target_os = "windows")]
    {
        // Для Windows используем консервативные настройки
        (500, 2000)
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        // Для Linux можно попробовать определить лучше
        // По умолчанию консервативные настройки
        (1000, 5000)
    }
}