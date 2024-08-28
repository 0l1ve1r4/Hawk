const RED_ANSI: &str = "\x1b[0;31m";
const GREEN_ANSI: &str = "\x1b[0;32m";
const YELLOW_ANSI: &str = "\x1b[0;33m";
const BLUE_ANSI: &str = "\x1b[0;34m";
const RESET_ANSI: &str = "\x1b[0m";

#[allow(dead_code)]
pub enum LogLevel {
    Debug,
    Success,
    Warning,
    Error,
}

pub fn debug(message: &str, log_level: LogLevel) {
    let color = match log_level {
        LogLevel::Debug => BLUE_ANSI,
        LogLevel::Success => GREEN_ANSI,
        LogLevel::Warning => YELLOW_ANSI,
        LogLevel::Error => RED_ANSI,
    };

    // Print the message with color and reset ANSI code
    println!("{}{}{}", color, message, RESET_ANSI);
}
