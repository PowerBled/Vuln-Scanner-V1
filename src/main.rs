mod scanner;
mod vulnerabilities;
mod utils;
mod web_scanner;
mod nvd_client;

use std::path::Path;
use colored::Colorize;
use std::time::Instant;
use indicatif::{ProgressBar, ProgressStyle};
use ctrlc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== Linux Vulnerability Scanner ===".bright_cyan().bold());
    println!("{}", "Author: PowerBled | Optimized for memory usage\n".dimmed());
    
    // Проверяем наличие файла с IP-адресами
    let ip_file = "ips.txt";
    if !Path::new(ip_file).exists() {
        eprintln!("{}", "Ошибка: файл ips.txt не найден!".red().bold());
        eprintln!("Создайте файл ips.txt с IP-адресами в формате:");
        eprintln!("192.168.1.0/24  # Рекомендуемый формат для тестирования");
        eprintln!("10.0.0.0/8      # Большая сеть (будет сканироваться полностью)");
        eprintln!("192.168.1.1-192.168.1.100");
        eprintln!("2001:db8::1-2001:db8::100 (IPv6-пока не поддерживается)");
        std::process::exit(1);
    }
    
    // Создаем директорию для результатов
    std::fs::create_dir_all("results")?;
    
    // Загружаем IP-адреса
    println!("{} Загружаем IP-адреса из файла...", "✓".green());
    let ip_ranges = utils::load_ip_ranges(ip_file)?;
    
    // Подсчитываем общее количество IP-адресов
    let total_ips = utils::count_total_ips(&ip_ranges);
    
    if total_ips == 0 {
        eprintln!("{} Не найдено IP-адресов для сканирования", "⚠".yellow());
        std::process::exit(1);
    }
    
    println!("{} Найдено {} IP-адресов для сканирования", "✓".green(), total_ips);
    
    // Автонастройка производительности
    println!("{} Автонастройка производительности...", "⚡".cyan());
    
    // Определяем сетевой интерфейс
    if let Some(iface) = utils::get_network_interface() {
        println!("{} Используется сетевой интерфейс: {}", "🔌".blue(), iface);
    }
    
    // Оценка пропускной способности
    let (concurrent_capacity, rate_capacity) = utils::estimate_network_capacity();
    println!("{} Оценка сетевой емкости: {} параллельных подключений, {}/сек", 
           "📊".blue(), concurrent_capacity, rate_capacity);
    
    // Настройки производительности с учетом пропускной способности
    let config = scanner::ScanConfig::optimized_for_range(total_ips);
    
    if total_ips > 1_000_000 {
        println!("{} Большой диапазон IP. Используем потоковую обработку.", "⚠".yellow());
    }
    
    println!("{} Настройки производительности:", "⚡".cyan());
    println!("  - Максимальная параллельность: {}", config.max_concurrent_tasks);
    println!("  - Таймаут соединения: {} мс", config.connection_timeout.as_millis());
    println!("  - Пакетный размер: {}", config.batch_size);
    println!("  - Rate limiting: {}/сек", config.rate_limit_per_second);
    
    if config.adaptive_rate_limiting {
        println!("  - Адаптивное rate limiting: включено");
    }
    
    if let Some(max_ips) = config.max_ips_to_scan {
        if max_ips < total_ips {
            println!("  - Максимальное количество IP для сканирования: {}", max_ips);
        }
    }
    
    if config.enable_web_deep_scan {
        println!("{} Включено глубокое сканирование веб-приложений", "🌐".blue());
    }
    
    println!("{} Включена проверка через NVD API", "🔐".blue());
    
    // Инициализируем сканер с оптимизированными настройками
    let scanner = scanner::HighPerformanceScanner::new(config).await?;
    
    // Настройка обработки Ctrl+C
    let scanner_for_signal = scanner.clone();
    ctrlc::set_handler(move || {
        println!("\n{} Получен сигнал Ctrl+C, останавливаем сканирование...", "⏸️".yellow());
        scanner_for_signal.stop();
    })?;
    
    // Запускаем сканирование
    println!("\n{} Запускаем высокопроизводительное сканирование...", "🚀".blue());
    println!("{} Используйте Ctrl+C для безопасной остановки", "⏸️".yellow());
    let start_time = Instant::now();
    
    // Создаем прогресс-бар
    let max_ips_to_scan = scanner.config().max_ips_to_scan.unwrap_or(total_ips);
    let pb = ProgressBar::new(max_ips_to_scan);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) | {per_sec} | активных задач: {active}")
        .unwrap()
        .progress_chars("#>-"));
    
    let vuln_count = scanner.scan_ips(&ip_ranges, Some(pb)).await?;
    
    let duration = start_time.elapsed();
    
    // Выводим статистику производительности
    let ips_per_second = max_ips_to_scan as f64 / duration.as_secs_f64();
    println!("\n{} Сканирование завершено за {:?}", "✓".green(), duration);
    println!("{} Производительность: {:.2} IP/сек", "📊".blue(), ips_per_second);
    println!("{} Найдено уязвимостей: {}", "🔍".blue(), vuln_count);
    
    if vuln_count > 0 {
        println!("{} Результаты сохранены в results/vulnerabilities.txt и results/vulnerabilities.csv", "💾".green());
        
        // Создаем сводный файл
        if let Ok(_summary) = utils::create_summary_file(vuln_count) {
            println!("{} Краткая сводка сохранена в results/summary.txt", "📋".yellow());
        }
    } else {
        println!("{} Уязвимостей не найдено", "✅".green());
    }
    
    // Сохраняем статистику
    utils::save_statistics(duration, total_ips, vuln_count, ips_per_second)?;
    
    Ok(())
}