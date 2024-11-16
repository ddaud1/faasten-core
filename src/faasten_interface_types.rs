use crate::fs::Function;

use super::fs::DirEntry;
use labeled::buckle::{Buckle, Component};
use serde::{Deserialize, Serialize};

/*************************************************
DENT OPEN
*************************************************/

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct DentOpen {
    pub fd: u64,
    pub entry: Option<dent_open::Entry>
}


pub mod dent_open {
    #[derive(serde::Deserialize, serde::Serialize, Debug)]
        pub enum Entry {
        Name(String),
        Facet(super::Buckle)
    }
}

/*************************************************
DENT KIND
*************************************************/

pub enum DentKind {
    DentDirectory = 0,
    DentFile = 1,
    DentFacetedDirectory = 2,
    DentGate = 3,
    DentService = 4,
    DentBlob = 5
}

impl From<&DirEntry> for DentKind {
    fn from(item: &DirEntry) -> Self {
        match item {
            DirEntry::Directory(_) => {DentKind::DentDirectory},
            DirEntry::File(_) => {DentKind::DentFile},
            DirEntry::Gate(_) => {DentKind::DentGate},
            DirEntry::Blob(_) => {DentKind::DentBlob},
            DirEntry::FacetedDirectory(_) => {DentKind::DentFacetedDirectory},
            DirEntry::Service(_) => {DentKind::DentService}
        }
    }
}

impl Into<i32> for DentKind {
    fn into(self) -> i32 {
        match self {
            DentKind::DentDirectory => {0}
            DentKind::DentFile => {1}
            DentKind::DentFacetedDirectory => {2}
            DentKind::DentGate => {3}
            DentKind::DentService => {4}
            DentKind::DentBlob => {5}
        }
    }
}

/*************************************************
DENT CREATE
*************************************************/

#[derive(Serialize, Deserialize, Debug)]
pub struct DentCreate {
    pub label: Option<Buckle>,
    pub kind: Option<dent_create::Kind>
}

pub mod dent_create {
    #[derive(super::Serialize, super::Deserialize, Debug)]
    pub enum Kind {
        Directory,
        File,
        FacetedDirectory,
        Gate(super::Gate),
        Service(super::Service),
        Blob
    }
}

/*************************************************
GATES
*************************************************/

#[derive(Serialize, Deserialize, Debug)]
pub struct Gate {
    pub kind: Option<gate::Kind>
}

pub mod gate {
    #[derive(super::Serialize, super::Deserialize, Debug)]
    pub enum Kind {
        Direct(super::DirectGate),
        Redirect(super::RedirectGate)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectGate {
    pub privilege: Option<Component>,
    pub invoker_integrity_clearance: Option<Component>,
    pub function: Option<Function>,
    pub declassify: Option<Component>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RedirectGate {
    pub privilege: Option<Component>,
    pub invoker_integrity_clearance: Option<Component>,
    pub gate: u64,
    pub declassify: Option<Component>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Service {
    pub privilege: Option<Component>,
    pub invoker_integrity_clearance: Option<Component>,
    pub taint: Option<Buckle>,
    pub url: String,
    pub verb: i32,
    pub headers: std::collections::HashMap<String, String>
}


/*************************************************
RESULTS
*************************************************/
#[derive(Serialize, Deserialize, Debug)]
pub struct DentResult {
    pub success: bool,
    pub fd: Option<u64>,
    pub data: Option<Vec<u8>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DentOpenResult {
    pub success: bool,
    pub fd: u64,
    pub kind: i32
}
