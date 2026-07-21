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
    use super::{MAX_ERROR_CHAIN_DEPTH, write_error_report};
    use std::error::Error;
    use std::fmt;
    use std::io::{self, Write};

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

    #[derive(Debug)]
    struct OwnedTestError {
        source: Option<Box<Self>>,
    }

    impl fmt::Display for OwnedTestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded")
        }
    }

    impl Error for OwnedTestError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source
                .as_deref()
                .map(|source| source as &(dyn Error + 'static))
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

    #[test]
    fn report_does_not_claim_omission_at_the_exact_depth_boundary() {
        let mut error = OwnedTestError { source: None };
        for _ in 0..MAX_ERROR_CHAIN_DEPTH {
            error = OwnedTestError {
                source: Some(Box::new(error)),
            };
        }
        let mut output = Vec::new();
        write_error_report(&mut output, &error).unwrap();
        assert_eq!(output, b"error: bounded\n");
    }

    #[test]
    fn report_propagates_failure_from_each_output_stage() {
        assert!(write_error_report(&mut FailAfterReports::new(0), &ROOT).is_err());
        assert!(write_error_report(&mut FailAfterReports::new(1), &ROOT).is_err());
        assert!(write_error_report(&mut FailAfterReports::new(1), &SelfSourcingError).is_err());
    }

    struct FailAfterReports {
        remaining: usize,
    }

    impl FailAfterReports {
        const fn new(remaining: usize) -> Self {
            Self { remaining }
        }
    }

    impl Write for FailAfterReports {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                Err(io::Error::other("output closed"))
            } else {
                self.remaining -= 1;
                Ok(buffer.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn write_fmt(&mut self, _arguments: fmt::Arguments<'_>) -> io::Result<()> {
            if self.remaining == 0 {
                Err(io::Error::other("output closed"))
            } else {
                self.remaining -= 1;
                Ok(())
            }
        }
    }
}
