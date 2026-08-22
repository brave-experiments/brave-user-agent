//! Task execution.
//!
//! Holds the label-aware tools and the turn loop. Tools take their routing arguments
//! from precommitted routing, never from model output, so a turn cannot be redirected
//! by the content it processes.

pub mod confirm;
pub mod diff;
pub mod glob;
pub mod replace;
pub mod report;
pub mod subscription;
pub mod tools;
pub mod turn;
pub mod workspace;

pub use confirm::{Confirmer, Decision, Intent, RefuseWrites, WriteRequest};
pub use report::{IgnoreReports, Reporter};
pub use subscription::ImportedSubscription;
pub use turn::{Outcome, Task, TurnError};
pub use workspace::{Workspace, WorkspaceError};
