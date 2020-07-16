#![allow(non_snake_case, dead_code)]
use std::ffi::c_void;

pub type BaseNetworkableClassPtr = *mut c_void;
pub type MonitorPtr = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BaseNetworkable {
    pub(crate) klass: BaseNetworkableClassPtr,
    pub(crate) monitor: MonitorPtr,
    pub(crate) object_m_CachedPtr: *mut c_void,
    pub(crate) justCreated_k__BackingField: bool,
    pub(crate) entityDestroy_deferredAction: u64,
    pub(crate) postNetworkUpdateComponents_collectionsList: *mut c_void,
    pub(crate) parentEntityRef: u64,
    pub(crate) children_baseEntitylist: *mut c_void,
    pub(crate) prefabID: u32,
    pub(crate) globalBroadcast: bool,
    pub(crate) net_Network_Networkable_o: *mut c_void,
    pub(crate) isDestroyed_k__BackingField: bool,
    pub(crate) prefabNameStrRef: *mut c_void,
    pub(crate) prefabNameWithoutExtensionStrRef: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DotNetList<T> {
    pub(crate) methodTablePtr: u32,
    pub(crate) length: u32,
    pub(crate) firstElement: T,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GameObjectManager {
    pub(crate) lastTaggedObject: *mut LastObjectBase,
    pub(crate) taggedObjects: *mut BaseObject,
    pub(crate) lastActiveObject: *mut LastObjectBase,
    pub(crate) activeObjects: *mut BaseObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BaseObject {
    pub(crate) pad_0x0000: libvirtdma::win::misc::Bytes8,
    pub(crate) nextObjectLink: *mut BaseObject,
    pub(crate) object: *mut GameObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LastObjectBase {
    pub(crate) pad_0x0000: libvirtdma::win::misc::Bytes16,
    pub(crate) lastObject: *mut GameObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EntityRef {
    pub(crate) ent_cached: *mut c_void, // BaseEntity_o*
    pub(crate) id_cached: u32,
}

#[repr(C)]
// #[derive(Clone, Copy, Debug)]
pub struct GameObject {
    pub(crate) pad_0x0000: [u8; 0x8],
    pub(crate) m_instanceID: i32,
    pub(crate) pad_0x000C: [u8; 0x24],
    pub(crate) m_label: i32,
    pub(crate) pad_0x0034: [u8; 0x4],
    pub(crate) m_size: i32,
    pub(crate) pad_0x003C: [u8; 0x4],
    pub(crate) m_capacity: i32,
    pub(crate) pad_0x0044: [u8; 0x4],
    pub(crate) m_layer: i32,
    pub(crate) m_tag: i16,
    pub(crate) m_isActive: u8,
    pub(crate) m_isActiveCached: u8,
    pub(crate) m_isDestroying: u8,
    pub(crate) m_isActivating: u8,
    pub(crate) pad_0x0052: [u8; 0x6],
    pub(crate) m_objectName: u64, // *String
}
