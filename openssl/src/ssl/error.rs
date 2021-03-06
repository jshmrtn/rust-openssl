use std::any::Any;
use std::error;
use std::error::Error as StdError;
use std::fmt;
use std::io;

use error::ErrorStack;
use ssl::MidHandshakeSslStream;

/// An SSL error.
#[derive(Debug)]
pub enum Error {
    /// The SSL session has been closed by the other end
    ZeroReturn,
    /// An attempt to read data from the underlying socket returned
    /// `WouldBlock`. Wait for read readiness and reattempt the operation.
    WantRead(io::Error),
    /// An attempt to write data from the underlying socket returned
    /// `WouldBlock`. Wait for write readiness and reattempt the operation.
    WantWrite(io::Error),
    /// The client certificate callback requested to be called again.
    WantX509Lookup,
    /// An error reported by the underlying stream.
    Stream(io::Error),
    /// An error in the OpenSSL library.
    Ssl(ErrorStack),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.description())?;
        if let Some(err) = self.cause() {
            write!(fmt, ": {}", err)
        } else {
            Ok(())
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ZeroReturn => "The SSL session was closed by the other end",
            Error::WantRead(_) => "A read attempt returned a `WouldBlock` error",
            Error::WantWrite(_) => "A write attempt returned a `WouldBlock` error",
            Error::WantX509Lookup => "The client certificate callback requested to be called again",
            Error::Stream(_) => "The underlying stream reported an error",
            Error::Ssl(_) => "The OpenSSL library reported an error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::WantRead(ref err) => Some(err),
            Error::WantWrite(ref err) => Some(err),
            Error::Stream(ref err) => Some(err),
            Error::Ssl(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error::Ssl(e)
    }
}

/// An error indicating that the operation can be immediately retried.
///
/// OpenSSL's [`SSL_read`] and [`SSL_write`] functions can return `SSL_ERROR_WANT_READ` even when
/// the underlying socket is performing blocking IO in certain cases. When this happens, the
/// the operation can be immediately retried.
///
/// To signal this event, the `io::Error` inside of [`Error::WantRead`] will be constructed around
/// a `RetryError`.
///
/// [`SSL_read`]: https://www.openssl.org/docs/manmaster/man3/SSL_read.html
/// [`SSL_write`]: https://www.openssl.org/docs/manmaster/man3/SSL_write.html
/// [`Error::WantRead`]: enum.Error.html#variant.WantRead
#[derive(Debug)]
pub struct RetryError;

impl fmt::Display for RetryError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(error::Error::description(self))
    }
}

impl error::Error for RetryError {
    fn description(&self) -> &str {
        "operation must be retried"
    }
}

/// An error or intermediate state after a TLS handshake attempt.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// Setup failed.
    SetupFailure(ErrorStack),
    /// The handshake failed.
    Failure(MidHandshakeSslStream<S>),
    /// The handshake was interrupted midway through. This error will never be returned for blocking streams.
    // FIXME change to WouldBlock
    Interrupted(MidHandshakeSslStream<S>),
}

impl<S: Any + fmt::Debug> StdError for HandshakeError<S> {
    fn description(&self) -> &str {
        match *self {
            HandshakeError::SetupFailure(_) => "stream setup failed",
            HandshakeError::Failure(_) => "the handshake failed",
            HandshakeError::Interrupted(_) => "the handshake was interrupted",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            HandshakeError::SetupFailure(ref e) => Some(e),
            HandshakeError::Failure(ref s) |
            HandshakeError::Interrupted(ref s) => Some(s.error()),
        }
    }
}

impl<S: Any + fmt::Debug> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(StdError::description(self))?;
        match *self {
            HandshakeError::SetupFailure(ref e) => write!(f, ": {}", e)?,
            HandshakeError::Failure(ref s) |
            HandshakeError::Interrupted(ref s) => {
                write!(f, ": {}", s.error())?;
                if let Some(err) = s.ssl().verify_result() {
                    write!(f, ": {}", err)?;
                }
            }
        }
        Ok(())
    }
}

impl<S> From<ErrorStack> for HandshakeError<S> {
    fn from(e: ErrorStack) -> HandshakeError<S> {
        HandshakeError::SetupFailure(e)
    }
}
