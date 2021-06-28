// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{ErrorKind, Read, Write};

use jni::objects::{AutoLocal, JObject, JValue};
use jni::sys::{jint, jsize};
use jni::JNIEnv;
use std::cmp::min;
use thiserror::Error as ThisError;

const MAX_BUFFER_SIZE: usize = 32 * 1024;

fn transmute_mut_byte_slice(slice: &mut [u8]) -> &mut [i8] {
    unsafe { &mut *(slice as *mut [u8] as *mut [i8]) }
}

fn transmute_byte_slice(slice: &[u8]) -> &[i8] {
    unsafe { &*(slice as *const [u8] as *const [i8]) }
}

#[derive(ThisError, Debug)]
pub enum IoError {
    #[error("failed to allocate byte array with capacity {0}")]
    BufferAllocation(usize),
    #[error("unexpected JNI return value of {0}")]
    UnexpectedJniReturnValue(jint),
    #[error("a JNI error occurred: {0}")]
    JniError(#[from] jni::errors::Error),
}

impl From<IoError> for std::io::Error {
    fn from(io_error: IoError) -> Self {
        Self::new(ErrorKind::Other, io_error)
    }
}

struct JNIByteArray<'a> {
    env: &'a JNIEnv<'a>,
    buffer: Option<AutoLocal<'a, 'a>>,
}

impl<'a> JNIByteArray<'a> {
    fn new(env: &'a JNIEnv<'a>) -> Self {
        Self { env, buffer: None }
    }

    /// Will panic if [`ensure_buffer_capacity`] has not been called yet.
    fn as_obj<'b>(&self) -> JObject<'b>
    where
        'a: 'b,
    {
        self.buffer.as_ref().unwrap().as_obj()
    }

    fn reallocate_buffer(&mut self, capacity: jsize) -> Result<(), IoError> {
        self.buffer = Some(self.env.auto_local(self.env.new_byte_array(capacity as jsize)?));
        Ok(())
    }

    fn ensure_buffer_capacity(&mut self, capacity: usize) -> Result<(), IoError> {
        if self.buffer.is_none() {
            self.reallocate_buffer(capacity as jsize)
        } else {
            let length: usize = self.env.get_array_length(*self.as_obj())? as usize;
            if length >= capacity {
                Ok(())
            } else {
                self.reallocate_buffer(capacity as jsize)
            }
        }
    }
}

struct JNIRead<'a> {
    env: &'a JNIEnv<'a>,
    input_stream: JObject<'a>,
    buffer: JNIByteArray<'a>,
}

impl<'a> Read for JNIRead<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let max_to_read: usize = min(buf.len(), MAX_BUFFER_SIZE);

        // ensure we're not trying to read nothing
        if max_to_read == 0 {
            return Ok(0);
        }

        self.buffer.ensure_buffer_capacity(max_to_read)?;

        let read = self
            .env
            .call_method(
                self.input_stream,
                "read",
                "([BII)I",
                &[
                    JValue::from(self.buffer.as_obj()),
                    JValue::from(0 as jint),
                    JValue::from(max_to_read as jint),
                ],
            )
            .map_err(|x| IoError::from(x))?
            .i()
            .unwrap();

        // Java can return 0 but returning 0 from Rust means EOF or input buf was 0 size so we abuse
        // ErrorKind::Interrupted to reflect when the underlying call returned no data for a
        // non-empty buffer.
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }

        // Java says we're at EOF so return the Rust equivalent
        if read == -1 {
            return Ok(0);
        }

        let readu = read as usize;
        if readu > max_to_read {
            return Err(IoError::UnexpectedJniReturnValue(read).into());
        }
        self.env
            .get_byte_array_region(*self.buffer.as_obj(), 0, transmute_mut_byte_slice(&mut buf[..readu]))
            .map_err(|x| IoError::from(x))?;
        Ok(readu)
    }
}

struct JNIWrite<'a> {
    env: &'a JNIEnv<'a>,
    output_stream: JObject<'a>,
    buffer: JNIByteArray<'a>,
}

impl<'a> Write for JNIWrite<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let max_to_write: usize = min(buf.len(), MAX_BUFFER_SIZE);

        // ensure we're not trying to write nothing
        if max_to_write == 0 {
            return Ok(0);
        }

        self.buffer.ensure_buffer_capacity(max_to_write)?;

        self.env
            .set_byte_array_region(*self.buffer.as_obj(), 0, transmute_byte_slice(&buf[..max_to_write]))
            .map_err(|x| IoError::from(x))?;
        self.env
            .call_method(
                self.output_stream,
                "write",
                "([BII)V",
                &[
                    JValue::from(self.buffer.as_obj()),
                    JValue::from(0 as jint),
                    JValue::from(max_to_write as jint),
                ],
            )
            .map_err(|x| IoError::from(x))?
            .v()
            .unwrap();
        Ok(max_to_write)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(self
            .env
            .call_method(self.output_stream, "flush", "()V", &[])
            .map_err(|x| IoError::from(x))?
            .v()
            .unwrap())
    }
}

pub fn convert_jni_input_stream_to_read_impl<'a>(env: &'a JNIEnv<'a>, input_stream: JObject<'a>) -> impl Read + 'a {
    JNIRead {
        env,
        input_stream,
        buffer: JNIByteArray::new(env),
    }
}

pub fn convert_jni_output_stream_to_write_impl<'a>(env: &'a JNIEnv<'a>, output_stream: JObject<'a>) -> impl Write + 'a {
    JNIWrite {
        env,
        output_stream,
        buffer: JNIByteArray::new(env),
    }
}
