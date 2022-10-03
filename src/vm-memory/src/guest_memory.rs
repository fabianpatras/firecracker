// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vm_memory_upstream::bitmap::AtomicBitmap;
use vm_memory_upstream::mmap::{Error as GuestMemoryMmapError, Iter as GuestMemoryIter};
use vm_memory_upstream::{GuestAddress, GuestMemory};

// using this ugly name so we can export `GuestMemoryMmap` internally
pub type GuestMemoryMmapUpstream<B> = vm_memory_upstream::GuestMemoryMmap<B>;
pub type GuestRegionMmap = vm_memory_upstream::GuestRegionMmap<Option<AtomicBitmap>>;
pub type GuestMmapRegion = vm_memory_upstream::MmapRegion<Option<AtomicBitmap>>;

/// Where does the memory come from?
#[derive(Clone, Debug)]
pub enum MemorySource {
    /// Memory region is provided by a memory device.
    Device,
    /// Memory region not provided by a memory device. In this case, it is noraml RAM.
    Normal,
}

/// Structure that tracks the validity of memory blocks inside a memory region.
/// The memory region is a contiguous physical address range inside the
/// guests' memory so it cannot have holes.
///
/// Valid block = Memory is backed by the VMM in some way (e.g. `mmap`ed into the
/// process, this is granted by upstream mmap implementation)
///     AND
/// The memory that backes is SAFE to R/W by the VMM (and susequently by the guest).
/// (it is `mmap`ed with Read/Write rights)
///
/// Invalid block = Memory is still backed by the VMM, but the guest can't access it.
/// And neither should the VMM!!! (e.g. `mmap`ed memory without access rights)
///
/// Only memory devices will use this structure.
#[derive(Clone, Debug)]
pub struct MemoryBlockTracker {
    // A reference to the memory region it tracks. Usefull especially for
    // the memory devices themselves that need to access the raw pointer.
    memory_region: Arc<GuestRegionMmap>,

    // Structure to track if the blocks are valid
    // Mutable by memory devices;
    bitmap: AtomicBitmap,
}

/// A wrapper over upstream GuestMemoryMmap.
#[derive(Debug, Clone)]
pub struct GuestMemoryMmap {
    // Original `guest_memory`; immutable; i.e. never modifying the created regions
    mmap: GuestMemoryMmapUpstream<Option<AtomicBitmap>>,

    // Information about who provides each memory region; immutable
    // `memory_source[i]` tells the memory source of `mmap.regions[i]`
    source: Arc<Mutex<Vec<MemorySource>>>,

    // Each memory device has its own memory block tracker. The key is the `id` of
    // the device as it is gueranteed to be unique.
    // This gets populated when a memory device is attached to the vmm.
    trackers: Arc<Mutex<HashMap<String, Arc<Mutex<MemoryBlockTracker>>>>>,
}

/// implementing the `GuestMemory` for our wrapper structure over the upstream
/// `GuestMemoryMmap` by using the implemented upstream methods (for now).
///
/// Methods `num_regions`, `find_region` and `iter` do not have a default
/// implementation. Implementing these methods needs a bit of thinking because
/// other alredy implemented methods might be based on how these behave.
/// Since we're introducing some regions that will have a special behaviour
/// (hot(un)pluggind, thus "modifying" how much memory we have)
/// we need to make sure we don't break the overall functionality.
///
/// - `num_regions`: returns the number of regions including the regions provided by the memory
///   device. It is not used anywhere else in the implementation of other methods (iside the trait
///   and inside the`GuestMemoryMmapUpstream`). It can passthough.
///
/// - `find_region`: many of the other methods use this in their default implementation, and then
///   many more methods use those methods as well (including reading and writing to the memory!!!)
///   so changing this will have (very) big consequences. We will change the default implementation
///   of the methods that use this one as needed. It will passthough.
///
/// - `iter`: this is only used to compute `last_addr`. We'll leave it unchanged for now and we'll
///   modify `last_addr` method to reflect the last address that is not provided by a memory device.
impl GuestMemory for GuestMemoryMmap {
    type R = GuestRegionMmap;
    type I = GuestMemoryMmapUpstream<Option<AtomicBitmap>>;

    fn num_regions(&self) -> usize {
        self.mmap.num_regions()
    }

    fn find_region(&self, addr: GuestAddress) -> Option<&Self::R> {
        self.mmap.find_region(addr)
    }

    fn iter(&self) -> GuestMemoryIter<'_, Option<AtomicBitmap>> {
        self.mmap.iter()
    }

    fn address_in_range(&self, addr: GuestAddress) -> bool {
        // first we use the underlying implementation to see if the address is inside a
        // a `GuestRegionMmap` region
        if !self.mmap.address_in_range(addr) {
            return false;
        }

        // TODO: Here comes the logic for when the address is inside the memory regions,
        // but we still need to check if the address is valid based on who provides that region.
        true
    }
}

/// Implementing methods for creating `GuestMemoryMmap`.
impl GuestMemoryMmap {
    /// This creates a `GuestMemoryMmap` without knowing which of the regions are provided
    /// by memory devices.
    pub fn from_regions(regions: Vec<GuestRegionMmap>) -> Result<Self, GuestMemoryMmapError> {
        let source = vec![MemorySource::Normal; regions.len()];
        Ok(Self {
            mmap: GuestMemoryMmapUpstream::from_regions(regions)?,
            source: Arc::new(Mutex::new(source)),
            trackers: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}
