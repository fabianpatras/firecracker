// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::vmm_config::memory::MemoryUpdateConfig;

use crate::parsed_request::{checked_id, Error, ParsedRequest};
use crate::request::Body;
use crate::VmmAction;

pub(crate) fn parse_patch_memory(
    body: &Body,
    path_second_token: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    match path_second_token {
        Some(&device_id) => Ok(ParsedRequest::new_sync(VmmAction::UpdateMemoryDevice(
            String::from(checked_id(device_id)?),
            serde_json::from_slice::<MemoryUpdateConfig>(body.raw())?,
        ))),
        None => Err(Error::EmptyID),
    }
}
