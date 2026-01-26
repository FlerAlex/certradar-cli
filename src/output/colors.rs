use colored::Colorize;

/// Format a security grade with appropriate color
pub fn format_grade(grade: &str) -> String {
    match grade {
        "A+" => grade.bright_green().bold().to_string(),
        "A" => grade.green().bold().to_string(),
        "B" => grade.yellow().bold().to_string(),
        "C" => grade.yellow().to_string(),
        "D" => grade.red().to_string(),
        "F" => grade.bright_red().bold().to_string(),
        _ => grade.to_string(),
    }
}

/// Format a boolean as check/cross with color
pub fn format_bool(value: bool) -> String {
    if value {
        "Yes".green().to_string()
    } else {
        "No".red().to_string()
    }
}

/// Format a boolean as check/cross symbol
pub fn format_check(value: bool) -> String {
    if value {
        "✓".green().to_string()
    } else {
        "✗".red().to_string()
    }
}

/// Format a severity with appropriate color
pub fn format_severity(severity: &str) -> String {
    match severity {
        "critical" => severity.bright_red().bold().to_string(),
        "warning" => severity.yellow().to_string(),
        "info" => severity.blue().to_string(),
        "good" => severity.green().to_string(),
        "bad" => severity.red().to_string(),
        _ => severity.to_string(),
    }
}

/// Format a status with appropriate color
pub fn format_status(status: &str) -> String {
    match status {
        "good" => "Good".green().to_string(),
        "warning" => "Warning".yellow().to_string(),
        "bad" => "Bad".red().to_string(),
        "info" => "Info".blue().to_string(),
        _ => status.to_string(),
    }
}

/// Format days remaining with appropriate color
pub fn format_days_remaining(days: i64) -> String {
    if days < 0 {
        format!("{} (EXPIRED)", days).bright_red().bold().to_string()
    } else if days <= 7 {
        format!("{}", days).bright_red().bold().to_string()
    } else if days <= 30 {
        format!("{}", days).yellow().to_string()
    } else if days <= 90 {
        format!("{}", days).to_string()
    } else {
        format!("{}", days).green().to_string()
    }
}

/// Create a section header
pub fn section_header(title: &str) -> String {
    let line = "─".repeat(60);
    format!("{}\n{}\n", title.bold(), line.dimmed())
}

/// Create a main header with box drawing
pub fn main_header(title: &str) -> String {
    let line = "═".repeat(60);
    format!("\n{}\n{}\n", title.bold().cyan(), line.cyan())
}
