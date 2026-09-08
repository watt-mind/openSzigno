//! Extraction: what one run was asked for, how the output tree is planned,
//! and how it is written.

pub(crate) mod names;
pub(crate) mod output_dir;
pub(crate) mod plan;
pub(crate) mod select;
pub(crate) mod write;

/// What one `extract` run was asked to do, apart from where it reads and
/// writes.
pub(crate) struct ExtractRequest<'a> {
    pub(crate) selectors: &'a [String],
    pub(crate) to_stdout: bool,
    pub(crate) recursive: bool,
    pub(crate) max_depth: u32,
}
