use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rocket::serde::uuid::Uuid;

pub fn random_string(number_of_chars: usize) -> String {
    let rng = thread_rng();
    rng.sample_iter(Alphanumeric)
        .take(number_of_chars)
        .map(char::from)
        .collect::<String>()
}

/// Creates a new abstract id for entities.
pub fn create_id() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}
