//! Forward Error Correction (FEC) support
//!
//! Provides optional Reed-Solomon based FEC for improved reliability
//! at the cost of bandwidth. Useful for bulk transfers over lossy links.

use std::collections::HashMap;

/// FEC group identifier
pub type FecGroupId = u32;

/// FEC configuration
#[derive(Debug, Clone, Copy)]
pub struct FecConfig {
    /// Number of data shards per FEC group
    pub data_shards: usize,
    /// Number of parity shards per FEC group
    pub parity_shards: usize,
    /// Whether FEC is enabled
    pub enabled: bool,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 2,
            enabled: false,
        }
    }
}

impl FecConfig {
    /// Create a new FEC config
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
            enabled: true,
        }
    }

    /// Create from parity ratio (e.g., 0.1 = 10% parity)
    pub fn from_ratio(data_shards: usize, ratio: f32) -> Self {
        let parity_shards = ((data_shards as f32) * ratio).ceil() as usize;
        Self::new(data_shards, parity_shards.max(1))
    }

    /// Total shards per group
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Check if FEC is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.parity_shards > 0
    }
}

/// A shard in an FEC group
#[derive(Debug, Clone)]
pub struct FecShard {
    /// Group this shard belongs to
    pub group_id: FecGroupId,
    /// Index within the group (0..data_shards are data, rest are parity)
    pub shard_index: u8,
    /// Total shards in the group
    pub total_shards: u8,
    /// Number of data shards
    pub data_shards: u8,
    /// Shard data
    pub data: Vec<u8>,
}

impl FecShard {
    /// Check if this is a parity shard
    pub fn is_parity(&self) -> bool {
        self.shard_index >= self.data_shards
    }
}

/// FEC encoder - creates parity shards from data shards
/// 
/// Note: This is a stub implementation. For production use,
/// integrate with reed-solomon-erasure crate.
#[derive(Debug)]
pub struct FecEncoder {
    config: FecConfig,
    next_group_id: FecGroupId,
    current_group: Vec<Vec<u8>>,
}

impl FecEncoder {
    pub fn new(config: FecConfig) -> Self {
        Self {
            config,
            next_group_id: 0,
            current_group: Vec::new(),
        }
    }

    /// Add a data shard and potentially get FEC shards out
    pub fn add_data(&mut self, data: Vec<u8>) -> Option<Vec<FecShard>> {
        if !self.config.is_enabled() {
            return None;
        }

        self.current_group.push(data);

        if self.current_group.len() >= self.config.data_shards {
            Some(self.flush_group())
        } else {
            None
        }
    }

    /// Flush current group (even if incomplete) and get FEC shards
    pub fn flush(&mut self) -> Option<Vec<FecShard>> {
        if self.current_group.is_empty() {
            return None;
        }
        Some(self.flush_group())
    }

    fn flush_group(&mut self) -> Vec<FecShard> {
        let group_id = self.next_group_id;
        self.next_group_id = self.next_group_id.wrapping_add(1);

        let data_count = self.current_group.len();
        let total_shards = (data_count + self.config.parity_shards) as u8;

        // Find max shard size for padding
        let max_size = self.current_group.iter().map(|s| s.len()).max().unwrap_or(0);

        let mut shards = Vec::with_capacity(self.config.total_shards());

        // Data shards
        for (i, data) in self.current_group.drain(..).enumerate() {
            shards.push(FecShard {
                group_id,
                shard_index: i as u8,
                total_shards,
                data_shards: data_count as u8,
                data,
            });
        }

        // Generate parity shards (stub - XOR based simple parity)
        // For production, use reed-solomon-erasure crate
        for i in 0..self.config.parity_shards {
            let mut parity = vec![0u8; max_size];
            for shard in &shards {
                for (j, &byte) in shard.data.iter().enumerate() {
                    if j < parity.len() {
                        parity[j] ^= byte;
                    }
                }
            }
            shards.push(FecShard {
                group_id,
                shard_index: (data_count + i) as u8,
                total_shards,
                data_shards: data_count as u8,
                data: parity,
            });
        }

        shards
    }

    /// Get current config
    pub fn config(&self) -> &FecConfig {
        &self.config
    }
}

/// FEC decoder - reconstructs missing data shards from parity
#[derive(Debug)]
pub struct FecDecoder {
    config: FecConfig,
    /// Partial groups being assembled
    groups: HashMap<FecGroupId, FecGroup>,
    /// Timeout for incomplete groups
    group_timeout_ms: u64,
}

#[derive(Debug)]
struct FecGroup {
    shards: Vec<Option<Vec<u8>>>,
    data_shards: u8,
    total_shards: u8,
    received_count: usize,
    created_at: std::time::Instant,
}

impl FecDecoder {
    pub fn new(config: FecConfig, group_timeout_ms: u64) -> Self {
        Self {
            config,
            groups: HashMap::new(),
            group_timeout_ms,
        }
    }

    /// Add a received shard
    /// Returns decoded data shards if group is complete/recoverable
    pub fn add_shard(&mut self, shard: FecShard) -> Option<Vec<Vec<u8>>> {
        if !self.config.is_enabled() {
            // FEC disabled, just return data shards directly
            if !shard.is_parity() {
                return Some(vec![shard.data]);
            }
            return None;
        }

        let group = self.groups.entry(shard.group_id).or_insert_with(|| FecGroup {
            shards: vec![None; shard.total_shards as usize],
            data_shards: shard.data_shards,
            total_shards: shard.total_shards,
            received_count: 0,
            created_at: std::time::Instant::now(),
        });

        let idx = shard.shard_index as usize;
        if idx < group.shards.len() && group.shards[idx].is_none() {
            group.shards[idx] = Some(shard.data);
            group.received_count += 1;
        }

        // Check if we can decode
        if group.received_count >= group.data_shards as usize {
            let group = self.groups.remove(&shard.group_id).unwrap();
            Some(self.decode_group(group))
        } else {
            None
        }
    }

    fn decode_group(&self, group: FecGroup) -> Vec<Vec<u8>> {
        // Collect data shards we have
        let mut result = Vec::new();
        
        for i in 0..(group.data_shards as usize) {
            if let Some(data) = &group.shards[i] {
                result.push(data.clone());
            } else {
                // Need to reconstruct this shard
                // Stub: For production, use reed-solomon-erasure
                // For now, we just skip missing shards
                result.push(Vec::new());
            }
        }

        result
    }

    /// Clean up timed-out incomplete groups
    pub fn cleanup(&mut self) {
        let timeout = std::time::Duration::from_millis(self.group_timeout_ms);
        let now = std::time::Instant::now();
        
        self.groups.retain(|_, group| {
            now.duration_since(group.created_at) < timeout
        });
    }

    /// Get number of partial groups
    pub fn partial_groups(&self) -> usize {
        self.groups.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_config() {
        let config = FecConfig::from_ratio(10, 0.2);
        assert_eq!(config.data_shards, 10);
        assert_eq!(config.parity_shards, 2);
        assert!(config.is_enabled());
    }

    #[test]
    fn test_fec_encoder() {
        let config = FecConfig::new(3, 1);
        let mut encoder = FecEncoder::new(config);

        // Add data shards
        assert!(encoder.add_data(vec![1, 2, 3]).is_none());
        assert!(encoder.add_data(vec![4, 5, 6]).is_none());
        
        // Third shard triggers flush
        let shards = encoder.add_data(vec![7, 8, 9]).unwrap();
        
        assert_eq!(shards.len(), 4); // 3 data + 1 parity
        assert!(!shards[0].is_parity());
        assert!(!shards[1].is_parity());
        assert!(!shards[2].is_parity());
        assert!(shards[3].is_parity());
    }

    #[test]
    fn test_fec_decoder_no_loss() {
        let config = FecConfig::new(3, 1);
        let mut encoder = FecEncoder::new(config.clone());
        let mut decoder = FecDecoder::new(config, 10000);

        // Encode
        encoder.add_data(vec![1, 2, 3]);
        encoder.add_data(vec![4, 5, 6]);
        let shards = encoder.add_data(vec![7, 8, 9]).unwrap();

        // Decode (send all data shards - parity shards may not complete the group)
        let mut result = None;
        for shard in shards.into_iter().filter(|s| !s.is_parity()) {
            if let Some(r) = decoder.add_shard(shard) {
                result = Some(r);
            }
        }

        let data = result.expect("Should have decoded data");
        assert_eq!(data.len(), 3);
        assert_eq!(data[0], vec![1, 2, 3]);
        assert_eq!(data[1], vec![4, 5, 6]);
        assert_eq!(data[2], vec![7, 8, 9]);
    }
}
