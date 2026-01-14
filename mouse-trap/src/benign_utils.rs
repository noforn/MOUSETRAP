pub fn calculate_primes(limit: u32) -> Vec<u32> {
    let mut primes = Vec::new();
    if limit >= 2 {
        primes.push(2);
    }
    for i in (3..limit + 1).step_by(2) {
        let mut is_prime = true;
        let sqrt = (i as f64).sqrt() as u32;
        for p in &primes {
            if *p > sqrt {
                break;
            }
            if i % *p == 0 {
                is_prime = false;
                break;
            }
        }
        if is_prime {
            primes.push(i);
        }
    }
    primes
}

pub fn harmless_string_op(input: &str) -> String {
    let mut reversed = input.chars().rev().collect::<String>();
    reversed.push_str("_processed");
    reversed
}

#[no_mangle]
pub extern "C" fn benign_export_1() {
    let _ = calculate_primes(50);
}

#[no_mangle]
pub extern "C" fn benign_export_2() {
    let _ = harmless_string_op("export_check");
}

pub mod poly_gen {
    include!(concat!(env!("OUT_DIR"), "/poly_generated.rs"));
}

pub struct Logger {
    pub level: u32,
    pub enabled: bool,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            level: 2, // INFO
            enabled: true,
        }
    }

    pub fn init(&self) {
        if self.enabled {
            // run junk code
            poly_gen::poly::random_logic();
            
            // fake init
            let _conf = poly_gen::poly::MetricConfig {
                endpoint: "https://api.datadoghq.com/v2/logs",
                retries: 3,
            };
        }
    }
}
