// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use event_manager::{EventOps, Events, MutEventSubscriber};
use logger::{debug, error, warn};
use utils::epoll::EventSet;

use crate::virtio::memory::device::Memory;
use crate::virtio::memory::GUEST_REQUESTS_INDEX;
use crate::virtio::VirtioDevice;

impl Memory {
    fn register_activate_event(&self, ops: &mut EventOps) {
        debug!("Memory.register_activate_event()");
        if let Err(err) = ops.add(Events::new(&self.activate_evt, EventSet::IN)) {
            error!("[Memory] Failed to register activate event: {}", err);
        }

        self.register_runtime_events(ops);
        if let Err(err) = ops.remove(Events::new(&self.activate_evt, EventSet::IN)) {
            error!("[Memory] Failed to un-register activate event: {}", err);
        }
    }

    fn register_runtime_events(&self, ops: &mut EventOps) {
        debug!("Memory.register_runtime_events()");
        if let Err(err) = ops.add(Events::new(
            &self.queue_evts[GUEST_REQUESTS_INDEX],
            EventSet::IN,
        )) {
            error!("[Memory] Failed to register inflate queue event: {}", err);
        }
    }
}

impl MutEventSubscriber for Memory {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();
        let supported_events = EventSet::IN;

        if !supported_events.contains(event_set) {
            warn!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            let virtq_quest_requests_ev_fd = self.queue_evts[GUEST_REQUESTS_INDEX].as_raw_fd();
            let activate_fd = self.activate_evt.as_raw_fd();

            match source {
                _ if source == virtq_quest_requests_ev_fd => {
                    debug!("virtq_quest_requests_ev_fd")
                }
                _ if source == activate_fd => {
                    debug!("activate_fd");
                    self.register_activate_event(ops);
                }
                _ => {
                    warn!(
                        "Memory [{}]: Spurious event received: {:?}",
                        self.id(),
                        source
                    );
                }
            }
        } else {
            warn!(
                "Memory [{}]: The device is not yet activated. Spurious event received: {:?}",
                self.id(),
                source
            );
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        debug!("Memory device [{}].init()", self.id());

        self.register_activate_event(ops);
    }
}

#[cfg(test)]
pub mod tests {}
