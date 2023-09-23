use std::path::PathBuf;
use std::str::FromStr;

use inquire::validator::Validation;
use openai::arkose::funcaptcha::Solver;

use crate::parse;

pub fn valid_url(
    s: &str,
) -> Result<Validation, Box<(dyn std::error::Error + Send + Sync + 'static)>> {
    if !s.is_empty() {
        match parse::parse_url(s) {
            Ok(_) => Ok(Validation::Valid),
            Err(err) => Ok(Validation::Invalid(
                inquire::validator::ErrorMessage::Custom(err.to_string()),
            )),
        }
    } else {
        Ok(Validation::Valid)
    }
}

pub fn valid_file_path(
    s: &str,
) -> Result<Validation, Box<(dyn std::error::Error + Send + Sync + 'static)>> {
    if !s.is_empty() {
        match PathBuf::from(s).is_file() {
            true => Ok(Validation::Valid),
            false => Ok(Validation::Invalid(
                inquire::validator::ErrorMessage::Custom(format!("file: {s} not exists")),
            )),
        }
    } else {
        Ok(Validation::Valid)
    }
}

pub fn valid_solver(
    s: &str,
) -> Result<Validation, Box<(dyn std::error::Error + Send + Sync + 'static)>> {
    if !s.is_empty() {
        match Solver::from_str(s) {
            Ok(_) => Ok(Validation::Valid),
            Err(err) => Ok(Validation::Invalid(
                inquire::validator::ErrorMessage::Custom(err.to_string()),
            )),
        }
    } else {
        Ok(Validation::Valid)
    }
}
