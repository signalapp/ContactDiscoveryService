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

    fn reallocate_buffer(&mut self, capacity: jsize) -> Result<(), IoError> {
        self.buffer = Some(self.env.auto_local(self.env.new_byte_array(capacity as jsize)?));
        Ok(())
    }

    fn ensure_buffer_capacity(&mut self, capacity: usize) -> Result<(), IoError> {
        if self.buffer.is_none() {
            self.reallocate_buffer(capacity as jsize)
        } else {
            let length: usize = self.env.get_array_length(*self.buffer.as_ref().unwrap().as_obj())? as usize;
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
        let mut to_read: usize = buf.len();
        self.buffer.ensure_buffer_capacity(min(to_read, MAX_BUFFER_SIZE))?;

        while to_read > 0 {
            let read = self
                .env
                .call_method(
                    self.input_stream,
                    "read",
                    "([BII)I",
                    &[
                        JValue::from(self.buffer.buffer.as_ref().unwrap().as_obj()),
                        JValue::from(0 as jint),
                        JValue::from(min(to_read, MAX_BUFFER_SIZE) as jint),
                    ],
                )
                .map_err(|x| IoError::from(x))?
                .i()
                .unwrap();
            if read == -1 {
                return Ok(buf.len() - to_read);
            }
            if (read as usize) > to_read {
                return Err(IoError::UnexpectedJniReturnValue(read).into());
            }
            let start = buf.len() - to_read;
            let end = min(start + MAX_BUFFER_SIZE, buf.len());
            self.env
                .get_byte_array_region(
                    *self.buffer.buffer.as_ref().unwrap().as_obj(),
                    0,
                    transmute_mut_byte_slice(&mut buf[start..end]),
                )
                .map_err(|x| IoError::from(x))?;
            to_read -= read as usize;
        }
        Ok(buf.len() - to_read)
    }
}

struct JNIWrite<'a> {
    env: &'a JNIEnv<'a>,
    output_stream: JObject<'a>,
    buffer: JNIByteArray<'a>,
}

impl<'a> Write for JNIWrite<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let mut to_write: usize = buf.len();
        self.buffer.ensure_buffer_capacity(min(to_write, MAX_BUFFER_SIZE))?;

        while to_write > 0 {
            let start = buf.len() - to_write;
            let end = min(start + MAX_BUFFER_SIZE, buf.len());
            self.env
                .set_byte_array_region(
                    *self.buffer.buffer.as_ref().unwrap().as_obj(),
                    0,
                    transmute_byte_slice(&buf[start..end]),
                )
                .map_err(|x| IoError::from(x))?;
            let written = min(to_write, MAX_BUFFER_SIZE);
            self.env
                .call_method(
                    self.output_stream,
                    "write",
                    "([BII)V",
                    &[
                        JValue::from(self.buffer.buffer.as_ref().unwrap().as_obj()),
                        JValue::from(0 as jint),
                        JValue::from(written as jint),
                    ],
                )
                .map_err(|x| IoError::from(x))?
                .v()
                .unwrap();
            to_write -= written;
        }
        Ok(buf.len())
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
