# Akash-Deploy-Rs

we maximize effort in ensuring we dont make maintaince of this crate complex and reuse scripting and templates for common workflows on maintining, testing, and adding new support workflows. We are able to avoid complexity and undesseary tech-debt in the future due to these actions now that we take in the present.

- use `cargo chec` replcaing `cargo check`, `cargo tes` in replace of `cargo test`, its reduces token count in output without reducing clarity.

- we just just files for the main surface area for dev ops. we value reusable template scripts to assist with automation of keeping up to date formatting and docs.
- we test with use of libraries and logic used in production libraries, not mock libraries. This is thanks to the open-source nature of akash network and all crates used, which has been able to strengthen our knowledge of the structure of building this gateway to akash network and console libraries.
