//! An in-memory [`ApplySink`] for tests and fuzzing.
//!
//! It records everything the engine asks for and enforces the sink
//! contract strictly, so tests catch engine mistakes: parents must exist,
//! nothing is created twice, writes arrive in order, hard links name an
//! existing file, and no operation goes through a path whose ancestor
//! already carries reparse data. A byte budget bounds its memory.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - NIST 800-53: SC-5 (Denial of Service Protection) - bounded memory
//   when used under fuzzing.

use std::collections::BTreeMap;
use std::io::ErrorKind;

use super::sink::{ApplySink, SinkError, SinkOp, SinkResult};
use crate::wim::metadata::{Attributes, FileTimes};
use crate::wim::names::{ImagePath, ShortName, StreamName};
use crate::wim::reparse::ReparseBuffer;

/// What a node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryNodeKind {
    /// A directory.
    Dir,
    /// A file.
    File,
}

/// One file or directory (shared by every name of a hard-linked file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryNode {
    /// What it is.
    pub kind: MemoryNodeKind,
    /// The unnamed stream.
    pub data: Vec<u8>,
    /// Named streams.
    pub streams: BTreeMap<String, Vec<u8>>,
    /// The whole reparse buffer set (header and data).
    pub reparse: Option<ReparseBuffer>,
    /// The descriptor set.
    pub security: Option<Vec<u8>>,
    /// The times set.
    pub times: Option<FileTimes>,
    /// The attributes set.
    pub attributes: Option<Attributes>,
}

impl MemoryNode {
    fn new(kind: MemoryNodeKind) -> Self {
        Self {
            kind,
            data: Vec::new(),
            streams: BTreeMap::new(),
            reparse: None,
            security: None,
            times: None,
            attributes: None,
        }
    }
}

/// An in-memory target.
#[derive(Debug, Clone)]
pub struct MemorySink {
    nodes: Vec<MemoryNode>,
    names: BTreeMap<ImagePath, usize>,
    short_names: BTreeMap<ImagePath, ShortName>,
    ops: Vec<(SinkOp, ImagePath)>,
    max_bytes: u64,
    used: u64,
}

impl Default for MemorySink {
    fn default() -> Self {
        Self::new()
    }
}

impl MemorySink {
    /// An empty target holding only the root, with a 1 GiB data budget.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(1 << 30)
    }

    /// An empty target with a data budget of `max_bytes`.
    #[must_use]
    pub fn with_limit(max_bytes: u64) -> Self {
        let mut names = BTreeMap::new();
        names.insert(ImagePath::root(), 0);
        Self {
            nodes: vec![MemoryNode::new(MemoryNodeKind::Dir)],
            names,
            short_names: BTreeMap::new(),
            ops: Vec::new(),
            max_bytes,
            used: 0,
        }
    }

    /// The node at `p`.
    #[must_use]
    pub fn node(&self, p: &ImagePath) -> Option<&MemoryNode> {
        self.names.get(p).and_then(|&i| self.nodes.get(i))
    }

    /// Every path, sorted, with its node.
    pub fn entries(&self) -> impl Iterator<Item = (&ImagePath, &MemoryNode)> {
        self.names
            .iter()
            .filter_map(|(p, &i)| self.nodes.get(i).map(|n| (p, n)))
    }

    /// True if `a` and `b` are names of one node (a hard link).
    #[must_use]
    pub fn same_node(&self, a: &ImagePath, b: &ImagePath) -> bool {
        matches!((self.names.get(a), self.names.get(b)), (Some(x), Some(y)) if x == y)
    }

    /// The short name set on `p`.
    #[must_use]
    pub fn short_name(&self, p: &ImagePath) -> Option<&ShortName> {
        self.short_names.get(p)
    }

    /// Every operation, in call order.
    #[must_use]
    pub fn ops(&self) -> &[(SinkOp, ImagePath)] {
        &self.ops
    }

    fn err(op: SinkOp, kind: ErrorKind) -> SinkError {
        SinkError::new(op, kind)
    }

    /// The node index of `p`, refusing paths below a reparse point.
    fn find(&self, op: SinkOp, p: &ImagePath) -> Result<usize, SinkError> {
        self.check_ancestors(op, p)?;
        self.names
            .get(p)
            .copied()
            .ok_or(Self::err(op, ErrorKind::NotFound))
    }

    fn check_ancestors(&self, op: SinkOp, p: &ImagePath) -> SinkResult {
        let c = p.components();
        for k in 0..c.len() {
            let mut a = ImagePath::root();
            for x in c.iter().take(k) {
                a = a.join(x.clone());
            }
            let n = self.node(&a).ok_or(Self::err(op, ErrorKind::NotFound))?;
            if n.kind != MemoryNodeKind::Dir || n.reparse.is_some() {
                return Err(Self::err(op, ErrorKind::InvalidInput));
            }
        }
        Ok(())
    }

    fn create(&mut self, op: SinkOp, p: &ImagePath, kind: MemoryNodeKind) -> SinkResult {
        if p.is_root() || self.names.contains_key(p) {
            return Err(Self::err(op, ErrorKind::AlreadyExists));
        }
        self.check_ancestors(op, p)?;
        self.nodes.push(MemoryNode::new(kind));
        self.names
            .insert(p.clone(), self.nodes.len().saturating_sub(1));
        Ok(())
    }

    fn node_mut(&mut self, op: SinkOp, p: &ImagePath) -> Result<&mut MemoryNode, SinkError> {
        let i = self.find(op, p)?;
        self.nodes
            .get_mut(i)
            .ok_or(Self::err(op, ErrorKind::NotFound))
    }

    fn log(&mut self, op: SinkOp, p: &ImagePath) {
        self.ops.push((op, p.clone()));
    }
}

impl ApplySink for MemorySink {
    fn create_dir(&mut self, p: &ImagePath) -> SinkResult {
        self.log(SinkOp::CreateDir, p);
        self.create(SinkOp::CreateDir, p, MemoryNodeKind::Dir)
    }

    fn create_file(&mut self, p: &ImagePath) -> SinkResult {
        self.log(SinkOp::CreateFile, p);
        self.create(SinkOp::CreateFile, p, MemoryNodeKind::File)
    }

    fn create_stream(&mut self, p: &ImagePath, s: &StreamName) -> SinkResult {
        self.log(SinkOp::CreateStream, p);
        let op = SinkOp::CreateStream;
        let n = self.node_mut(op, p)?;
        if n.streams.contains_key(s.as_str()) {
            return Err(Self::err(op, ErrorKind::AlreadyExists));
        }
        n.streams.insert(s.as_str().to_owned(), Vec::new());
        Ok(())
    }

    fn write(
        &mut self,
        p: &ImagePath,
        stream: Option<&StreamName>,
        off: u64,
        data: &[u8],
    ) -> SinkResult {
        self.log(SinkOp::Write, p);
        let op = SinkOp::Write;
        let len = u64::try_from(data.len()).map_err(|_| Self::err(op, ErrorKind::InvalidInput))?;
        let used = self
            .used
            .checked_add(len)
            .filter(|&u| u <= self.max_bytes)
            .ok_or(Self::err(op, ErrorKind::OutOfMemory))?;
        let n = self.node_mut(op, p)?;
        if n.reparse.is_some() {
            return Err(Self::err(op, ErrorKind::InvalidInput));
        }
        let buf = match stream {
            None if n.kind == MemoryNodeKind::File => &mut n.data,
            None => return Err(Self::err(op, ErrorKind::InvalidInput)),
            Some(s) => n
                .streams
                .get_mut(s.as_str())
                .ok_or(Self::err(op, ErrorKind::NotFound))?,
        };
        if u64::try_from(buf.len()).ok() != Some(off) {
            return Err(Self::err(op, ErrorKind::InvalidInput));
        }
        buf.extend_from_slice(data);
        self.used = used;
        Ok(())
    }

    fn hard_link(&mut self, existing: &ImagePath, new: &ImagePath) -> SinkResult {
        self.log(SinkOp::HardLink, new);
        let op = SinkOp::HardLink;
        let i = self.find(op, existing)?;
        if self.nodes.get(i).map(|n| n.kind) != Some(MemoryNodeKind::File) {
            return Err(Self::err(op, ErrorKind::InvalidInput));
        }
        if new.is_root() || self.names.contains_key(new) {
            return Err(Self::err(op, ErrorKind::AlreadyExists));
        }
        self.check_ancestors(op, new)?;
        self.names.insert(new.clone(), i);
        Ok(())
    }

    fn set_reparse(&mut self, p: &ImagePath, buf: &ReparseBuffer) -> SinkResult {
        self.log(SinkOp::SetReparse, p);
        let op = SinkOp::SetReparse;
        // A directory reparse point must have no children.
        if self.names.keys().any(|k| {
            k.components().len() > p.components().len()
                && k.components().starts_with(p.components())
        }) {
            return Err(Self::err(op, ErrorKind::InvalidInput));
        }
        let n = self.node_mut(op, p)?;
        if n.reparse.is_some() || !n.data.is_empty() || !n.streams.is_empty() {
            return Err(Self::err(op, ErrorKind::InvalidInput));
        }
        n.reparse = Some(buf.clone());
        Ok(())
    }

    fn set_security(&mut self, p: &ImagePath, sd: &[u8]) -> SinkResult {
        self.log(SinkOp::SetSecurity, p);
        self.node_mut(SinkOp::SetSecurity, p)?.security = Some(sd.to_vec());
        Ok(())
    }

    fn set_short_name(&mut self, p: &ImagePath, n: &ShortName) -> SinkResult {
        self.log(SinkOp::SetShortName, p);
        self.find(SinkOp::SetShortName, p)?;
        self.short_names.insert(p.clone(), n.clone());
        Ok(())
    }

    fn set_times(&mut self, p: &ImagePath, t: &FileTimes) -> SinkResult {
        self.log(SinkOp::SetTimes, p);
        self.node_mut(SinkOp::SetTimes, p)?.times = Some(*t);
        Ok(())
    }

    fn set_attributes(&mut self, p: &ImagePath, a: Attributes) -> SinkResult {
        self.log(SinkOp::SetAttributes, p);
        if p.is_root() {
            return Err(Self::err(SinkOp::SetAttributes, ErrorKind::InvalidInput));
        }
        self.node_mut(SinkOp::SetAttributes, p)?.attributes = Some(a);
        Ok(())
    }
}
