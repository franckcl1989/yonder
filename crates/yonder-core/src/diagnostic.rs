use std::error::Error;
use std::io::{self, Write};

const MAX_ERROR_CHAIN_DEPTH: usize = 16;

/// Writes a bounded, de-duplicated error chain for a failing CLI process.
pub fn write_error_report(
    output: &mut impl Write,
    error: &(dyn Error + 'static),
) -> io::Result<()> {
    let mut previous = error.to_string();
    writeln!(output, "error: {previous}")?;

    let mut source = error.source();
    for _ in 0..MAX_ERROR_CHAIN_DEPTH {
        let Some(error) = source else {
            return Ok(());
        };
        let message = error.to_string();
        if message != previous {
            writeln!(output, "caused by: {message}")?;
        }
        previous = message;
        source = error.source();
    }

    if source.is_some() {
        writeln!(output, "caused by: additional error context was omitted")?;
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::write_error_report;
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct TestError {
        message: &'static str,
        source: Option<&'static TestError>,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.message)
        }
    }

    impl Error for TestError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source.map(|source| source as &(dyn Error + 'static))
        }
    }

    #[derive(Debug)]
    struct SelfSourcingError;

    impl fmt::Display for SelfSourcingError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("cycle")
        }
    }

    impl Error for SelfSourcingError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self)
        }
    }

    static LEAF: TestError = TestError {
        message: "precise cause",
        source: None,
    };
    static TRANSPARENT: TestError = TestError {
        message: "outer context",
        source: Some(&LEAF),
    };
    static ROOT: TestError = TestError {
        message: "outer context",
        source: Some(&TRANSPARENT),
    };

    #[test]
    fn report_preserves_causes_without_repeating_transparent_context() {
        let mut output = Vec::new();
        write_error_report(&mut output, &ROOT).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "error: outer context\ncaused by: precise cause\n"
        );
    }

    #[test]
    fn report_bounds_malformed_error_chains() {
        let mut output = Vec::new();
        write_error_report(&mut output, &SelfSourcingError).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "error: cycle\ncaused by: additional error context was omitted\n"
        );
    }
}
